package com.github.highcumontoa.gateway.session;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import com.github.highcumontoa.gateway.audit.AuditAction;
import com.github.highcumontoa.gateway.audit.AuditEntry;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.audit.AuditOutcome;
import com.github.highcumontoa.gateway.auth.CredentialStore;
import com.github.highcumontoa.gateway.auth.UserAccount;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import com.github.highcumontoa.gateway.token.JwtService;
import com.github.highcumontoa.gateway.token.RefreshFailureReason;
import com.github.highcumontoa.gateway.token.RefreshResult;
import org.springframework.stereotype.Service;

/**
 * 会话族生命周期权威（进程内内存实现）。
 *
 * <p>边界判定与时钟偏差容忍同样确定、可复现（均以秒级时钟比较，含边界放行）：
 * <ul>
 *   <li>总续期上限：{@code now > createdAt + sessionMaxLifetime} 才拒绝，边界上（相等）放行；</li>
 *   <li>闲置超时：{@code now > lastActivityAt + sessionIdleTimeout} 才拒绝，边界上放行；</li>
 *   <li>单次刷新令牌时效：{@code now > expiresAt} 才判 EXPIRED，边界上放行。</li>
 * </ul>
 *
 * <p>同一会话族内的刷新消耗、闲置/上限判定与下线动作都在该会话对象的锁内完成，
 * 因而“下线”与“并发刷新”之间存在确定的先后（可线性化），互不产生撕裂结果。
 */
@Service
public class SessionService {

    /** 单条刷新令牌记录；used 用 CAS 保证并发下有且仅有一次消耗成功。 */
    private record RefreshRec(String token, String familyId, Instant expiresAt, AtomicBoolean used) {}

    /** 会话族可变状态；所有变更都在 {@code this} 锁内进行。 */
    private static final class Session {
        final String familyId;
        final String subject;
        final Instant createdAt;
        final Instant absoluteDeadline;
        final Map<String, RefreshRec> refreshTokens = new ConcurrentHashMap<>();
        volatile Instant lastActivityAt;
        volatile boolean terminated;
        /** 终止来源：EXPLICIT（主动下线/吊销）或 REUSE（重用检测触发）。 */
        volatile String terminateReason;

        Session(String familyId, String subject, Instant createdAt, Instant absoluteDeadline) {
            this.familyId = familyId;
            this.subject = subject;
            this.createdAt = createdAt;
            this.absoluteDeadline = absoluteDeadline;
            this.lastActivityAt = createdAt;
        }
    }

    private final GatewayProperties properties;
    private final Clock clock;
    private final AuditLog auditLog;
    private final JwtService jwtService;
    private final CredentialStore credentialStore;
    private final java.security.SecureRandom random = new java.security.SecureRandom();

    /** familyId -> 会话。 */
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    /** 刷新令牌 -> familyId，便于 O(1) 定位。 */
    private final Map<String, String> tokenIndex = new ConcurrentHashMap<>();

    public SessionService(GatewayProperties properties, Clock clock, AuditLog auditLog,
                          JwtService jwtService, CredentialStore credentialStore) {
        this.properties = properties;
        this.clock = clock;
        this.auditLog = auditLog;
        this.jwtService = jwtService;
        this.credentialStore = credentialStore;
    }

    /** 凭证校验通过后建立会话并签发初始令牌对；返回 [accessToken, refreshToken, familyId]。 */
    public String[] openSession(String subject) {
        UserAccount account = credentialStore.find(subject)
                .orElseThrow(() -> new IllegalArgumentException("unknown user: " + subject));
        Instant now = Instant.now(clock);
        String familyId = UUID.randomUUID().toString();
        Session session = new Session(familyId, subject, now,
                now.plus(properties.getSessionMaxLifetime()));
        sessions.put(familyId, session);
        String refreshToken = mintRefreshToken(session, now);
        String accessToken = jwtService.issue(subject, account.roles(), familyId);
        audit(AuditAction.SESSION_CREATED, subject, familyId, AuditOutcome.SUCCESS, true,
                "会话建立 absoluteDeadline=" + session.absoluteDeadline
                        + " idleTimeout=" + properties.getSessionIdleTimeout());
        return new String[]{accessToken, refreshToken, familyId};
    }

    /** 轮换刷新令牌。判定顺序见类注释；失败原因彼此可区分。 */
    public RefreshResult rotate(String refreshToken) {
        String familyId = refreshToken == null ? null : tokenIndex.get(refreshToken);
        if (familyId == null) {
            audit(AuditAction.REFRESH, null, null, AuditOutcome.UNKNOWN_TOKEN, false,
                    "刷新令牌不存在于任何会话族");
            return RefreshResult.fail(RefreshFailureReason.UNKNOWN_TOKEN);
        }
        Session session = sessions.get(familyId);
        Instant now = Instant.now(clock);

        // 会话级判定与令牌消耗放在同一把会话锁内，保证与下线并发时结果确定。
        RefreshResult result;
        String outcome;
        String detail;
        synchronized (session) {
            RefreshRec rec = session.refreshTokens.get(refreshToken);
            if (session.terminated) {
                outcome = AuditOutcome.REVOKED;
                detail = "会话族已终止(" + session.terminateReason + ")";
                result = RefreshResult.fail(RefreshFailureReason.FAMILY_REVOKED);
            } else if (now.isAfter(rec.expiresAt())) {
                outcome = AuditOutcome.EXPIRED;
                detail = "单次刷新令牌过期 now=" + now + " exp=" + rec.expiresAt();
                result = RefreshResult.fail(RefreshFailureReason.EXPIRED);
            } else if (now.isAfter(session.absoluteDeadline)) {
                outcome = AuditOutcome.MAX_LIFETIME;
                detail = "超过总续期上限 now=" + now + " deadline=" + session.absoluteDeadline;
                result = RefreshResult.fail(RefreshFailureReason.TOTAL_LIFETIME_REACHED);
            } else if (now.isAfter(session.lastActivityAt.plus(properties.getSessionIdleTimeout()))) {
                outcome = AuditOutcome.IDLE_TIMEOUT;
                detail = "闲置超时 now=" + now + " lastActivity=" + session.lastActivityAt
                        + " idleTimeout=" + properties.getSessionIdleTimeout();
                result = RefreshResult.fail(RefreshFailureReason.IDLE_TIMEOUT);
            } else if (!rec.used().compareAndSet(false, true)) {
                // 并发/重放：CAS 失败者视为重用，立即吊销整个会话族且不可恢复。
                session.terminated = true;
                session.terminateReason = "REUSE";
                outcome = AuditOutcome.REUSE_DETECTED;
                detail = "已消耗刷新令牌被再次使用，整族吊销";
                result = RefreshResult.fail(RefreshFailureReason.ALREADY_USED_REUSE_DETECTED);
            } else {
                UserAccount account = credentialStore.find(session.subject).orElse(null);
                if (account == null || !account.enabled()) {
                    session.terminated = true;
                    session.terminateReason = "EXPLICIT";
                    outcome = AuditOutcome.REVOKED;
                    detail = "用户档案不存在或已停用，吊销会话族";
                    result = RefreshResult.fail(RefreshFailureReason.FAMILY_REVOKED);
                } else {
                    Instant issueAt = Instant.now(clock);
                    String newRefreshToken = mintRefreshToken(session, issueAt);
                    session.lastActivityAt = issueAt;
                    String newAccessToken = jwtService.issue(account.username(), account.roles(),
                            session.familyId);
                    outcome = AuditOutcome.SUCCESS;
                    detail = "轮换成功 lastActivity=" + issueAt;
                    result = RefreshResult.ok(newAccessToken, newRefreshToken);
                }
            }
        }
        boolean success = result.isSuccess();
        audit(AuditAction.REFRESH, session.subject, familyId, outcome, success, detail);
        return result;
    }

    /** 凭刷新令牌显式吊销其所属会话族（未知令牌保持静默无操作，兼容既有 /auth/revoke 语义）。 */
    public void revokeFamilyByToken(String refreshToken) {
        String familyId = refreshToken == null ? null : tokenIndex.get(refreshToken);
        if (familyId == null) {
            return;
        }
        Session session = sessions.get(familyId);
        if (session == null) {
            return;
        }
        synchronized (session) {
            if (!session.terminated) {
                session.terminated = true;
                session.terminateReason = "EXPLICIT";
                audit(AuditAction.SESSION_TERMINATED, session.subject, familyId,
                        AuditOutcome.REVOKED, true, "凭刷新令牌显式吊销会话族");
            }
        }
    }

    /** 会话族是否已被吊销（测试/门面观察用）。 */
    public boolean isFamilyRevokedByToken(String refreshToken) {
        String familyId = refreshToken == null ? null : tokenIndex.get(refreshToken);
        if (familyId == null) {
            return false;
        }
        Session session = sessions.get(familyId);
        return session != null && session.terminated;
    }

    /**
     * 访问令牌守卫：所属会话族当前是否仍活跃。
     * 注意：闲置超时/总寿命只阻止“刷新换发新令牌”，不提前作废尚未到期的访问令牌；
     * 只有显式下线/吊销/重用检测会让访问令牌立即失效。
     */
    public boolean isSessionActive(String familyId) {
        Session session = familyId == null ? null : sessions.get(familyId);
        return session != null && !session.terminated;
    }

    /** 列出某主体的全部会话（元数据视图，不含任何凭据），按建立时间升序。 */
    public List<SessionInfo> listSessions(String subject) {
        List<SessionInfo> infos = new ArrayList<>();
        for (Session session : sessions.values()) {
            if (session.subject.equals(subject)) {
                SessionState state = session.terminated ? SessionState.TERMINATED : SessionState.ACTIVE;
                infos.add(new SessionInfo(session.familyId, session.subject, session.createdAt,
                        session.lastActivityAt, state));
            }
        }
        infos.sort(java.util.Comparator.comparing(SessionInfo::createdAt));
        return List.copyOf(infos);
    }

    /** 下线指定主体的指定会话。null 表示成功；否则为可区分的失败原因。重复下线幂等成功。 */
    public SessionFailureReason terminate(String subject, String familyId) {
        Session session = familyId == null ? null : sessions.get(familyId);
        if (session == null) {
            return SessionFailureReason.UNKNOWN_SESSION;
        }
        if (!session.subject.equals(subject)) {
            audit(AuditAction.SESSION_TERMINATED, subject, familyId, AuditOutcome.DENIED, false,
                    "拒绝跨主体下线：会话归属 " + session.subject);
            return SessionFailureReason.SESSION_NOT_OWNED_BY_SUBJECT;
        }
        synchronized (session) {
            if (!session.terminated) {
                session.terminated = true;
                session.terminateReason = "EXPLICIT";
                audit(AuditAction.SESSION_TERMINATED, subject, familyId, AuditOutcome.SUCCESS, true,
                        "用户主动下线单个会话");
            }
        }
        return null;
    }

    /** 一次性下线某主体的全部会话，返回被下线（本次真正由活跃转终止）的会话数。 */
    public int terminateAll(String subject) {
        int count = 0;
        for (Session session : sessions.values()) {
            if (!session.subject.equals(subject)) {
                continue;
            }
            synchronized (session) {
                if (!session.terminated) {
                    session.terminated = true;
                    session.terminateReason = "EXPLICIT";
                    count++;
                    audit(AuditAction.SESSION_TERMINATED, subject, session.familyId,
                            AuditOutcome.SUCCESS, true, "全部下线：终止会话");
                }
            }
        }
        audit(AuditAction.SESSIONS_TERMINATED_ALL, subject, null, AuditOutcome.SUCCESS, true,
                "全部下线完成，本次终止会话数=" + count);
        return count;
    }

    private String mintRefreshToken(Session session, Instant now) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String token = HexFormat.of().formatHex(bytes);
        session.refreshTokens.put(token, new RefreshRec(token, session.familyId,
                now.plus(properties.getRefreshTokenTtl()), new AtomicBoolean(false)));
        tokenIndex.put(token, session.familyId);
        return token;
    }

    private void audit(String action, String subject, String familyId, String outcome,
                       boolean success, String detail) {
        auditLog.record(new AuditEntry(-1L, Instant.now(clock), action, subject, familyId,
                outcome, success, null, null, null, detail));
    }
}
