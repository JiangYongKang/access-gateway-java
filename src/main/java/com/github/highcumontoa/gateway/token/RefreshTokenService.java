package com.github.highcumontoa.gateway.token;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import com.github.highcumontoa.gateway.auth.CredentialStore;
import com.github.highcumontoa.gateway.auth.UserAccount;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import org.springframework.stereotype.Service;

/**
 * 刷新令牌生命周期：
 *  - 轮换：每次刷新消耗旧令牌并签发新令牌（同一会话族）。
 *  - 重用检测：已消耗的令牌再次被使用时，整个会话族立即吊销且不可恢复。
 *  - 并发：同一令牌的消耗通过 CAS 保证，并发刷新有且仅有一次成功。
 *  - 吊销：显式吊销或重用检测触发，族内所有令牌（含未使用的新令牌）一律拒绝。
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
    private final Map<String, RefreshRecord> tokens = new ConcurrentHashMap<>();
    private final Set<String> revokedFamilies = ConcurrentHashMap.newKeySet();
    private final SecureRandom random = new SecureRandom();

    public RefreshTokenService(GatewayProperties properties, JwtService jwtService,
                               CredentialStore credentialStore, Clock clock) {
        this.properties = properties;
        this.jwtService = jwtService;
        this.credentialStore = credentialStore;
        this.clock = clock;
    }

    /** 凭证校验通过后签发初始令牌对：{accessToken, refreshToken}。 */
    public String[] issueInitialTokenPair(String username) {
        UserAccount account = credentialStore.find(username)
                .orElseThrow(() -> new IllegalArgumentException("unknown user: " + username));
        String familyId = UUID.randomUUID().toString();
        String refreshToken = newRefreshToken(username, familyId);
        String accessToken = jwtService.issue(username, account.roles(), familyId);
        return new String[]{accessToken, refreshToken};
    }

    /** 轮换刷新令牌。失败原因可区分，见 {@link RefreshFailureReason}。 */
    public RefreshResult rotate(String refreshToken) {
        RefreshRecord record = refreshToken == null ? null : tokens.get(refreshToken);
        if (record == null) {
            return RefreshResult.fail(RefreshFailureReason.UNKNOWN_TOKEN);
        }
        if (revokedFamilies.contains(record.familyId())) {
            return RefreshResult.fail(RefreshFailureReason.FAMILY_REVOKED);
        }
        if (Instant.now(clock).isAfter(record.expiresAt())) {
            return RefreshResult.fail(RefreshFailureReason.EXPIRED);
        }
        // CAS 消耗：并发下仅一个线程获胜；失败者视为重用并吊销整个会话族。
        if (!record.used().compareAndSet(false, true)) {
            revokedFamilies.add(record.familyId());
            return RefreshResult.fail(RefreshFailureReason.ALREADY_USED_REUSE_DETECTED);
        }
        UserAccount account = credentialStore.find(record.username()).orElse(null);
        if (account == null || !account.enabled()) {
            revokedFamilies.add(record.familyId());
            return RefreshResult.fail(RefreshFailureReason.FAMILY_REVOKED);
        }
        String newRefreshToken = newRefreshToken(record.username(), record.familyId());
        String accessToken = jwtService.issue(record.username(), account.roles(), record.familyId());
        return RefreshResult.ok(accessToken, newRefreshToken);
    }

    /** 显式吊销该令牌所属会话族。 */
    public void revokeFamily(String refreshToken) {
        RefreshRecord record = tokens.get(refreshToken);
        if (record != null) {
            revokedFamilies.add(record.familyId());
        }
    }

    /** 仅供测试/审计观察：会话族是否已被吊销。 */
    public boolean isFamilyRevoked(String refreshToken) {
        RefreshRecord record = tokens.get(refreshToken);
        return record != null && revokedFamilies.contains(record.familyId());
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
