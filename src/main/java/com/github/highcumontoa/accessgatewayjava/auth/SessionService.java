package com.github.highcumontoa.accessgatewayjava.auth;

import com.github.highcumontoa.accessgatewayjava.config.GatewayProperties;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 刷新令牌会话族管理：签发、原子轮换、重用检测与吊销。
 *
 * <p>并发模型：每个会话族一个监视器锁。同一刷新令牌被并发使用时，
 * 只有一个线程能在临界区内完成轮换（currentTokenId 被替换），
 * 其余线程进入临界区后发现令牌编号不匹配，判定为重用并整族吊销。
 * 因此同一刷新令牌并发使用有且仅有一次成功，且重用后该族不可恢复。
 *
 * <p>tokenIndex 永不删除：已轮换的旧令牌编号仍映射到族，用于重用检测。
 */
@Service
public class SessionService {

    /** 轮换结果。 */
    public record RotateOutcome(String familyId, String subject, String audience,
                                Set<String> roles, String newRefreshTokenId) {
    }

    private final GatewayProperties props;
    private final Clock clock;
    private final Map<String, RefreshFamily> families = new ConcurrentHashMap<>();
    private final Map<String, String> tokenIndex = new ConcurrentHashMap<>();
    private final AtomicLong sequence = new AtomicLong();

    public SessionService(GatewayProperties props, Clock clock) {
        this.props = props;
        this.clock = clock;
    }

    /** 登录成功后创建会话族，返回首个刷新令牌编号。 */
    public String createFamily(String subject, String audience, Set<String> roles) {
        String familyId = "fam-" + sequence.incrementAndGet();
        String tokenId = "rt-" + sequence.incrementAndGet();
        Instant now = clock.instant();
        RefreshFamily family = new RefreshFamily(familyId, subject, audience, Set.copyOf(roles),
                now, now.plusSeconds(props.getToken().getRefreshTtlSeconds()), tokenId);
        families.put(familyId, family);
        tokenIndex.put(tokenId, familyId);
        return tokenId;
    }

    /** 按刷新令牌编号查会话族（不触发任何状态变更）。 */
    public RefreshFamily familyOf(String tokenId) {
        String familyId = tokenIndex.get(tokenId);
        return familyId == null ? null : families.get(familyId);
    }

    /**
     * 原子轮换：同一刷新令牌并发使用时，有且仅有一次成功。
     *
     * @throws AuthException 重用/吊销/不存在等，原因见 {@link AuthError}
     */
    public RotateOutcome rotate(String presentedTokenId) {
        RefreshFamily family = familyOf(presentedTokenId);
        if (family == null) {
            throw new AuthException(AuthError.FAMILY_NOT_FOUND,
                    "刷新令牌编号不属于任何会话族: " + presentedTokenId);
        }
        synchronized (family) {
            if (family.isRevoked()) {
                throw new AuthException(AuthError.REFRESH_TOKEN_REVOKED,
                        "会话族 " + family.getFamilyId() + " 已吊销: " + family.getRevokeReason());
            }
            if (clock.instant().isAfter(family.getExpiresAt())) {
                family.revoke("expired");
                throw new AuthException(AuthError.INVALID_REFRESH_TOKEN,
                        "会话族 " + family.getFamilyId() + " 已过期");
            }
            if (!presentedTokenId.equals(family.getCurrentTokenId())) {
                family.revoke("reuse-detected: presented=" + presentedTokenId
                        + " current=" + family.getCurrentTokenId());
                throw new AuthException(AuthError.REFRESH_TOKEN_REUSED,
                        "检测到刷新令牌重用，会话族 " + family.getFamilyId() + " 已整体吊销且不可恢复");
            }
            String newTokenId = "rt-" + sequence.incrementAndGet();
            family.setCurrentTokenId(newTokenId);
            tokenIndex.put(newTokenId, family.getFamilyId());
            return new RotateOutcome(family.getFamilyId(), family.getSubject(),
                    family.getAudience(), family.getRoles(), newTokenId);
        }
    }

    /** 吊销指定会话族（显式登出）。 */
    public boolean revokeFamily(String familyId, String reason) {
        RefreshFamily family = families.get(familyId);
        if (family == null) {
            return false;
        }
        synchronized (family) {
            family.revoke(reason);
        }
        return true;
    }

    /** 会话族只读快照（供审计/管理接口）。 */
    public List<RefreshFamily> listFamilies() {
        return new ArrayList<>(families.values());
    }
}
