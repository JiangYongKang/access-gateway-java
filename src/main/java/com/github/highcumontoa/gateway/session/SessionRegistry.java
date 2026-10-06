package com.github.highcumontoa.gateway.session;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 进程内会话注册表：跟踪每个会话族（sessionId == 刷新令牌 fam）的
 * 建立时间、最近活动时间与状态。它是以下判定的唯一事实来源：
 *  - 访问令牌的会话级失效（被下线后签名/时效正常也立即拒绝）；
 *  - 刷新续期上限（闲置超时 / 总最长可续期时间）。
 *
 * 并发语义：吊销与刷新并发时不会产生中间态——要么刷新先完成
 * （随后吊销使新访问令牌立即失效、新刷新令牌不可用），要么吊销先生效
 * （刷新以 FAMILY_REVOKED 失败）；重复判定结论一致。
 */
@Component
public class SessionRegistry {

    /** 单个会话的可变状态；状态迁移通过 synchronized 保证原子。 */
    private static final class SessionState {
        private final String sessionId;
        private final String username;
        private final Instant createdAt;
        private volatile Instant lastActivityAt;
        private volatile boolean revoked;

        SessionState(String sessionId, String username, Instant now) {
            this.sessionId = sessionId;
            this.username = username;
            this.createdAt = now;
            this.lastActivityAt = now;
            this.revoked = false;
        }

        synchronized void touch(Instant now) {
            if (!revoked) {
                lastActivityAt = now;
            }
        }

        /** @return true 表示本次调用完成了 ACTIVE -> REVOKED 迁移。 */
        synchronized boolean revoke() {
            if (revoked) {
                return false;
            }
            revoked = true;
            return true;
        }

        SessionInfo snapshot() {
            return new SessionInfo(sessionId, username, createdAt, lastActivityAt,
                    revoked ? SessionInfo.Status.REVOKED : SessionInfo.Status.ACTIVE);
        }
    }

    private final Clock clock;
    private final ConcurrentHashMap<String, SessionState> sessions = new ConcurrentHashMap<>();

    public SessionRegistry(Clock clock) {
        this.clock = clock;
    }

    /** 建立会话，返回 sessionId（即令牌 fam 声明）。 */
    public String establish(String username) {
        String sessionId = UUID.randomUUID().toString();
        sessions.put(sessionId, new SessionState(sessionId, username, Instant.now(clock)));
        return sessionId;
    }

    /** 刷新活动：活跃会话的最近活动时间推进到当前时刻；已吊销会话不再更新。 */
    public void touch(String sessionId) {
        SessionState state = sessions.get(sessionId);
        if (state != null) {
            state.touch(Instant.now(clock));
        }
    }

    /** 会话是否已被吊销。未知会话视为未吊销（兼容直接签发/重启前的令牌）。 */
    public boolean isRevoked(String sessionId) {
        SessionState state = sessionId == null ? null : sessions.get(sessionId);
        return state != null && state.revoked;
    }

    /**
     * 下线单个会话。幂等：已吊销的会话再次下线仍返回 true；
     * 会话不存在返回 false。
     */
    public boolean revoke(String sessionId) {
        SessionState state = sessions.get(sessionId);
        if (state == null) {
            return false;
        }
        state.revoke();
        return true;
    }

    /** 下线某用户全部会话，返回本次由活跃转为吊销的会话数量。 */
    public int revokeAllForUser(String username) {
        int count = 0;
        for (SessionState state : sessions.values()) {
            if (state.username.equals(username) && state.revoke()) {
                count++;
            }
        }
        return count;
    }

    /** 某用户的活跃会话列表（按建立时间升序，不含已吊销）。 */
    public List<SessionInfo> sessionsFor(String username) {
        List<SessionInfo> result = new ArrayList<>();
        for (SessionState state : sessions.values()) {
            if (state.username.equals(username) && !state.revoked) {
                result.add(state.snapshot());
            }
        }
        result.sort(Comparator.comparing(SessionInfo::createdAt).thenComparing(SessionInfo::sessionId));
        return result;
    }

    /** 查询单个会话快照（含已吊销）。 */
    public Optional<SessionInfo> find(String sessionId) {
        SessionState state = sessionId == null ? null : sessions.get(sessionId);
        return state == null ? Optional.empty() : Optional.of(state.snapshot());
    }
}
