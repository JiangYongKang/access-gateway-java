package com.github.highcumontoa.gateway;

import java.time.Duration;
import java.time.Instant;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.auth.CredentialStore;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import com.github.highcumontoa.gateway.session.SessionRegistry;
import com.github.highcumontoa.gateway.support.MutableClock;
import com.github.highcumontoa.gateway.token.JwtService;
import com.github.highcumontoa.gateway.token.KeyManager;
import com.github.highcumontoa.gateway.token.RefreshFailureReason;
import com.github.highcumontoa.gateway.token.RefreshResult;
import com.github.highcumontoa.gateway.token.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 会话续期上限：闲置超时（session-idle-timeout）与总最长可续期时间
 * （session-max-lifetime）。边界规则与既有过期判定一致：
 * now > 边界 才失效，边界上仍有效；边界上/外 1 秒结论确定可复现。
 */
class SessionRenewalLimitTest {
    private static final Logger log = LoggerFactory.getLogger(SessionRenewalLimitTest.class);
    private static final Instant T0 = Instant.parse("2026-10-07T00:00:00Z");
    private static final Duration IDLE = Duration.ofHours(2);
    private static final Duration MAX_LIFETIME = Duration.ofHours(6);

    private GatewayProperties properties;
    private MutableClock clock;
    private SessionRegistry sessionRegistry;
    private RefreshTokenService refreshService;

    @BeforeEach
    void setUp() {
        properties = new GatewayProperties();
        properties.setSessionIdleTimeout(IDLE);
        properties.setSessionMaxLifetime(MAX_LIFETIME);
        clock = new MutableClock(T0);
        KeyManager keyManager = new KeyManager(properties, clock);
        sessionRegistry = new SessionRegistry(clock);
        JwtService jwtService = new JwtService(properties, keyManager, clock, sessionRegistry);
        refreshService = new RefreshTokenService(properties, jwtService, new CredentialStore(), clock,
                sessionRegistry, new AuditLog());
    }

    @Test
    void idleTimeoutBoundaryIsDeterministic() {
        String[] pair = refreshService.issueInitialTokenPair("alice");
        // 边界上：now == lastActivity + idle -> 仍有效，且轮换推进最近活动时间
        clock.advance(IDLE);
        RefreshResult atBoundary = refreshService.rotate(pair[1]);
        log.info("输入=now=lastActivity+idle(边界上), 判定依据=now<=边界视为有效, 结论=success={}", atBoundary.isSuccess());
        assertTrue(atBoundary.isSuccess());

        // 边界外 1 秒：now > lastActivity + idle -> 闲置超时
        clock.advance(IDLE.plusSeconds(1));
        RefreshResult beyond = refreshService.rotate(atBoundary.refreshToken());
        RefreshResult repeated = refreshService.rotate(atBoundary.refreshToken());
        log.info("输入=now=lastActivity+idle+1s(边界外), 判定依据=now>边界, 结论={} / 重复={}",
                beyond.failureReason(), repeated.failureReason());
        assertEquals(RefreshFailureReason.SESSION_IDLE_TIMEOUT, beyond.failureReason());
        assertEquals(RefreshFailureReason.SESSION_IDLE_TIMEOUT, repeated.failureReason(), "重复验证结论一致");
    }

    @Test
    void maxLifetimeBoundaryIsDeterministic() {
        String[] pair = refreshService.issueInitialTokenPair("alice");
        // 边界上：now == createdAt + maxLifetime -> 仍有效（途中保持活跃避免闲置超时）
        String current = pair[1];
        for (int i = 0; i < 5; i++) {
            clock.advance(Duration.ofHours(1));
            RefreshResult r = refreshService.rotate(current);
            assertTrue(r.isSuccess(), "第 " + i + " 次轮换应成功");
            current = r.refreshToken();
        }
        clock.advance(Duration.ofHours(1)); // now == T0 + 6h == createdAt + maxLifetime
        RefreshResult atBoundary = refreshService.rotate(current);
        log.info("输入=now=createdAt+maxLifetime(边界上), 判定依据=now<=边界视为有效, 结论=success={}", atBoundary.isSuccess());
        assertTrue(atBoundary.isSuccess());

        // 边界外 1 秒：族内任何刷新令牌都不能再换发
        clock.advance(Duration.ofSeconds(1));
        RefreshResult beyond = refreshService.rotate(atBoundary.refreshToken());
        RefreshResult repeated = refreshService.rotate(atBoundary.refreshToken());
        log.info("输入=now=createdAt+maxLifetime+1s(边界外), 判定依据=now>边界, 结论={} / 重复={}",
                beyond.failureReason(), repeated.failureReason());
        assertEquals(RefreshFailureReason.SESSION_MAX_LIFETIME_EXCEEDED, beyond.failureReason());
        assertEquals(RefreshFailureReason.SESSION_MAX_LIFETIME_EXCEEDED, repeated.failureReason(), "重复验证结论一致");
    }

    @Test
    void continuousRotationCannotLiveForever() {
        String[] pair = refreshService.issueInitialTokenPair("alice");
        String current = pair[1];
        int rotations = 0;
        RefreshResult last = null;
        // 每 30 分钟轮换一次（远低于闲置超时），最终必然撞上总上限
        while (true) {
            clock.advance(Duration.ofMinutes(30));
            last = refreshService.rotate(current);
            if (!last.isSuccess()) {
                break;
            }
            current = last.refreshToken();
            rotations++;
            assertTrue(rotations < 100, "连续轮换不得无限续命");
        }
        log.info("输入=每30分钟连续轮换, 判定依据=总会话寿命不得超过maxLifetime, 结论=轮换{}次后以{}终止",
                rotations, last.failureReason());
        assertEquals(RefreshFailureReason.SESSION_MAX_LIFETIME_EXCEEDED, last.failureReason());
        assertEquals(12, rotations, "6h 上限 / 30min 间隔 = 12 次成功轮换");
    }

    @Test
    void failureReasonsAreDistinguishable() {
        // 闲置超时
        String[] idlePair = refreshService.issueInitialTokenPair("alice");
        clock.advance(IDLE.plusSeconds(1));
        RefreshResult idle = refreshService.rotate(idlePair[1]);
        // 总上限（另一会话：保持活跃持续轮换，直到越过总上限）
        String[] maxPair = refreshService.issueInitialTokenPair("bob");
        String bobCurrent = maxPair[1];
        RefreshResult maxed = null;
        for (int i = 0; i < 10; i++) {
            clock.advance(Duration.ofHours(1));
            RefreshResult r = refreshService.rotate(bobCurrent);
            if (!r.isSuccess()) {
                maxed = r;
                break;
            }
            bobCurrent = r.refreshToken();
        }
        assertNotNull(maxed, "持续活跃的会话最终必须撞上总上限");
        // 吊销
        String[] revokedPair = refreshService.issueInitialTokenPair("admin");
        refreshService.revokeFamily(revokedPair[1]);
        RefreshResult revoked = refreshService.rotate(revokedPair[1]);

        log.info("输入=三种失败场景, 判定依据=闲置/总上限/吊销分别判定, 结论=idle={} max={} revoked={}",
                idle.failureReason(), maxed.failureReason(), revoked.failureReason());
        assertEquals(RefreshFailureReason.SESSION_IDLE_TIMEOUT, idle.failureReason());
        assertEquals(RefreshFailureReason.SESSION_MAX_LIFETIME_EXCEEDED, maxed.failureReason());
        assertEquals(RefreshFailureReason.FAMILY_REVOKED, revoked.failureReason());
        assertNotEquals(idle.failureReason(), maxed.failureReason());
        assertNotEquals(maxed.failureReason(), revoked.failureReason());
    }

    @Test
    void reuseDetectionStillWorksWithSessionLimits() {
        String[] pair = refreshService.issueInitialTokenPair("alice");
        RefreshResult first = refreshService.rotate(pair[1]);
        assertTrue(first.isSuccess());
        RefreshResult reuse = refreshService.rotate(pair[1]);
        log.info("输入=已消耗令牌再次使用, 判定依据=重用检测吊销会话族, 结论={}", reuse.failureReason());
        assertEquals(RefreshFailureReason.ALREADY_USED_REUSE_DETECTED, reuse.failureReason());
        assertTrue(refreshService.isFamilyRevoked(pair[1]));
        // 族吊销优先于续期上限判定：即使越过闲置超时，结论仍是 FAMILY_REVOKED
        clock.advance(IDLE.plusSeconds(1));
        assertEquals(RefreshFailureReason.FAMILY_REVOKED, refreshService.rotate(first.refreshToken()).failureReason());
    }
}
