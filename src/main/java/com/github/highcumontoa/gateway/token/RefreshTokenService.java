package com.github.highcumontoa.gateway.token;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import com.github.highcumontoa.gateway.audit.AuditEventType;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.auth.CredentialStore;
import com.github.highcumontoa.gateway.auth.UserAccount;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import com.github.highcumontoa.gateway.session.SessionInfo;
import com.github.highcumontoa.gateway.session.SessionRegistry;
import org.springframework.stereotype.Service;

/**
 * 刷新令牌生命周期：
 *  - 轮换：每次刷新消耗旧令牌并签发新令牌（同一会话族）。
 *  - 重用检测：已消耗的令牌再次被使用时，整个会话族立即吊销且不可恢复。
 *  - 并发：同一令牌的消耗通过 CAS 保证，并发刷新有且仅有一次成功。
 *  - 吊销：显式吊销或重用检测触发，族内所有令牌（含未使用的新令牌）一律拒绝。
 *  - 续期上限：会话自建立起的总最长可续期时间（session-max-lifetime）与
 *    闲置超时（session-idle-timeout）两道边界；判定规则与既有过期判定一致——
 *    now > 边界 才失效，边界上仍有效，确定且可复现。
 * 会话状态（建立/活动/吊销）由 SessionRegistry 统一维护，吊销后访问令牌立即失效。
 */
@Service
public class RefreshTokenService {

    /** 刷新令牌记录：used 标志保证原子消耗。 */
    private record RefreshRecord(String token, String familyId, String username,
                                 Instant expiresAt, AtomicBoolean used) {}

    private final GatewayProperties properties;
    private final JwtService jwtService;
    private final CredentialStore credentialStore;
    private final Clock clock;
    private final SessionRegistry sessionRegistry;
    private final AuditLog auditLog;
    private final Map<String, RefreshRecord> tokens = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public RefreshTokenService(GatewayProperties properties, JwtService jwtService,
                               CredentialStore credentialStore, Clock clock,
                               SessionRegistry sessionRegistry, AuditLog auditLog) {
        this.properties = properties;
        this.jwtService = jwtService;
        this.credentialStore = credentialStore;
        this.clock = clock;
        this.sessionRegistry = sessionRegistry;
        this.auditLog = auditLog;
    }

    /** 凭证校验通过后签发初始令牌对：{accessToken, refreshToken}，同时建立会话。 */
    public String[] issueInitialTokenPair(String username) {
        UserAccount account = credentialStore.find(username)
                .orElseThrow(() -> new IllegalArgumentException("unknown user: " + username));
        String familyId = sessionRegistry.establish(username);
        String refreshToken = newRefreshToken(username, familyId);
        String accessToken = jwtService.issue(username, account.roles(), familyId);
        auditLog.record(AuditEventType.SESSION_ESTABLISHED, username, familyId, account.roles(),
                "session", "establish", true, "会话建立");
        return new String[]{accessToken, refreshToken};
    }

    /** 轮换刷新令牌。失败原因可区分，见 {@link RefreshFailureReason}。 */
    public RefreshResult rotate(String refreshToken) {
        RefreshRecord record = refreshToken == null ? null : tokens.get(refreshToken);
        if (record == null) {
            return RefreshResult.fail(RefreshFailureReason.UNKNOWN_TOKEN);
        }
        Instant now = Instant.now(clock);
        if (sessionRegistry.isRevoked(record.familyId())) {
            return auditAndFail(record, RefreshFailureReason.FAMILY_REVOKED);
        }
        if (now.isAfter(record.expiresAt())) {
            return auditAndFail(record, RefreshFailureReason.EXPIRED);
        }
        // 续期上限：与会话无关的令牌（注册表中没有记录）跳过这两道边界。
        SessionInfo session = sessionRegistry.find(record.familyId()).orElse(null);
        if (session != null) {
            if (now.isAfter(session.lastActivityAt().plus(properties.getSessionIdleTimeout()))) {
                return auditAndFail(record, RefreshFailureReason.SESSION_IDLE_TIMEOUT);
            }
            if (now.isAfter(session.createdAt().plus(properties.getSessionMaxLifetime()))) {
                return auditAndFail(record, RefreshFailureReason.SESSION_MAX_LIFETIME_EXCEEDED);
            }
        }
        // CAS 消耗：并发下仅一个线程获胜；失败者视为重用并吊销整个会话族。
        if (!record.used().compareAndSet(false, true)) {
            sessionRegistry.revoke(record.familyId());
            auditLog.record(AuditEventType.REFRESH_REUSE_DETECTED, record.username(), record.familyId(),
                    null, "session", "refresh", false, "刷新令牌重用检测，会话族已吊销");
            return RefreshResult.fail(RefreshFailureReason.ALREADY_USED_REUSE_DETECTED);
        }
        // 消耗后再确认一次会话状态：与并发下线竞争时，保证不签发新令牌。
        if (sessionRegistry.isRevoked(record.familyId())) {
            return auditAndFail(record, RefreshFailureReason.FAMILY_REVOKED);
        }
        UserAccount account = credentialStore.find(record.username()).orElse(null);
        if (account == null || !account.enabled()) {
            sessionRegistry.revoke(record.familyId());
            return auditAndFail(record, RefreshFailureReason.FAMILY_REVOKED);
        }
        String newRefreshToken = newRefreshToken(record.username(), record.familyId());
        String accessToken = jwtService.issue(record.username(), account.roles(), record.familyId());
        sessionRegistry.touch(record.familyId());
        auditLog.record(AuditEventType.SESSION_REFRESHED, record.username(), record.familyId(),
                account.roles(), "session", "refresh", true, "刷新轮换成功");
        return RefreshResult.ok(accessToken, newRefreshToken);
    }

    /** 显式吊销该令牌所属会话族。 */
    public void revokeFamily(String refreshToken) {
        RefreshRecord record = tokens.get(refreshToken);
        if (record != null) {
            sessionRegistry.revoke(record.familyId());
        }
    }

    /** 仅供测试/审计观察：会话族是否已被吊销。 */
    public boolean isFamilyRevoked(String refreshToken) {
        RefreshRecord record = tokens.get(refreshToken);
        return record != null && sessionRegistry.isRevoked(record.familyId());
    }

    private RefreshResult auditAndFail(RefreshRecord record, RefreshFailureReason reason) {
        auditLog.record(AuditEventType.SESSION_REFRESHED, record.username(), record.familyId(),
                null, "session", "refresh", false, reason.name());
        return RefreshResult.fail(reason);
    }

    private String newRefreshToken(String username, String familyId) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String token = HexFormat.of().formatHex(bytes);
        tokens.put(token, new RefreshRecord(token, familyId, username,
                Instant.now(clock).plus(properties.getRefreshTokenTtl()), new AtomicBoolean(false)));
        return token;
    }
}
