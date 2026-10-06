package com.github.highcumontoa.gateway;

import java.time.Duration;
import java.time.Instant;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.auth.CredentialStore;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import com.github.highcumontoa.gateway.support.MutableClock;
import com.github.highcumontoa.gateway.session.SessionService;
import com.github.highcumontoa.gateway.token.JwtService;
import com.github.highcumontoa.gateway.token.KeyManager;
import com.github.highcumontoa.gateway.token.RefreshFailureReason;
import com.github.highcumontoa.gateway.token.RefreshResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/** 会话族续期上限：闲置超时与总寿命边界（边界上放行、外一秒拒绝，结论稳定可复现）。 */
class SessionLifetimeBoundaryTest {
    private static final Logger log = LoggerFactory.getLogger(SessionLifetimeBoundaryTest.class);

    private GatewayProperties properties;
    private MutableClock clock;
    private SessionService sessionService;

    @BeforeEach
    void setUp() {
        properties = new GatewayProperties();
        // 用紧凑、整秒的时长让边界确定性可算
        properties.setSessionIdleTimeout(Duration.ofMinutes(10));
        properties.setSessionMaxLifetime(Duration.ofMinutes(60));
        properties.setRefreshTokenTtl(Duration.ofMinutes(120));
        clock = new MutableClock(Instant.parse("2026-10-01T00:00:00Z"));
        KeyManager keyManager = new KeyManager(properties, clock);
        JwtService jwtService = new JwtService(properties, keyManager, clock);
        sessionService = new SessionService(properties, clock, new AuditLog(), jwtService,
                new CredentialStore());
    }

    @Test
    void idleTimeoutAtBoundaryIsAllowed() {
        String[] s = sessionService.openSession("alice"); // lastActivity = t0
        clock.advance(Duration.ofMinutes(10)); // 距上次活动恰好 10m（含边界）
        RefreshResult atBoundary = sessionService.rotate(s[1]);
        log.info("输入=闲置边界上(now-lastActivity=10m), 判定依据=now<=lastActivity+idle含边界, 结论={}",
                atBoundary.isSuccess());
        assertTrue(atBoundary.isSuccess());
    }

    @Test
    void idleTimeoutOneSecondOutsideIsRejected() {
        String[] s = sessionService.openSession("alice"); // lastActivity = t0
        clock.advance(Duration.ofMinutes(10).plusSeconds(1)); // 距上次活动 10m+1s
        RefreshResult outside = sessionService.rotate(s[1]);
        log.info("输入=闲置边界外1秒, 判定依据=now>lastActivity+idle, 结论={}", outside.failureReason());
        assertEquals(RefreshFailureReason.IDLE_TIMEOUT, outside.failureReason());

        // 结论稳定可复现：同一令牌与族内旧令牌再验证仍是 IDLE_TIMEOUT
        assertEquals(RefreshFailureReason.IDLE_TIMEOUT, sessionService.rotate(s[1]).failureReason());
        // 闲置不吊销：族对应会话仍标记活跃（区别于下线/重用导致的访问令牌立即失效）
        assertTrue(sessionService.isSessionActive(s[2]));
    }

    @Test
    void totalLifetimeBoundaryInclusiveEvenWithContinuousRotation() {
        String[] pair = sessionService.openSession("alice");
        String rt = pair[1];
        // 在总寿命内持续轮换（每 5 分钟一次，远小于闲置 10 分钟），证明不能无限续命
        for (int minute = 5; minute < 60; minute += 5) {
            clock.advance(Duration.ofMinutes(5));
            RefreshResult r = sessionService.rotate(rt);
            assertTrue(r.isSuccess(), "第 " + minute + " 分钟仍在总寿命内，应轮换成功");
            rt = r.refreshToken();
        }
        // 此时 now = t0 + 55m，lastActivity 也持续更新

        // 再到边界上：now == createdAt + maxLifetime = t0+60m（闲置也未超）
        clock.advance(Duration.ofMinutes(5));
        RefreshResult atBoundary = sessionService.rotate(rt);
        log.info("输入=总寿命边界上(now-created=60m)且一直在轮换, 判定依据=now<=created+max含边界, 结论={}",
                atBoundary.isSuccess());
        assertTrue(atBoundary.isSuccess());
        rt = atBoundary.refreshToken();

        // 边界外 1 秒：即便刚刚才活动（无闲置），也因总上限拒绝
        clock.advance(Duration.ofSeconds(1));
        RefreshResult outside = sessionService.rotate(rt);
        log.info("输入=总寿命边界外1秒(持续轮换中), 判定依据=now>created+max, 结论={}",
                outside.failureReason());
        assertEquals(RefreshFailureReason.TOTAL_LIFETIME_REACHED, outside.failureReason());

        // 可复现：族内任何刷新令牌都不能换出新令牌
        assertEquals(RefreshFailureReason.TOTAL_LIFETIME_REACHED,
                sessionService.rotate(rt).failureReason());
        assertEquals(RefreshFailureReason.TOTAL_LIFETIME_REACHED,
                sessionService.rotate(pair[1]).failureReason());
    }

    @Test
    void revocationReasonIsDistinctFromTimeouts() {
        String[] pair = sessionService.openSession("bob");
        sessionService.revokeFamilyByToken(pair[1]);
        clock.advance(Duration.ofMinutes(2)); // 远未到闲置/总上限
        RefreshResult revoked = sessionService.rotate(pair[1]);
        log.info("输入=显式吊销后刷新(时间边界均未到), 判定依据=会话族已吊销优先于时间判定, 结论={}",
                revoked.failureReason());
        assertEquals(RefreshFailureReason.FAMILY_REVOKED, revoked.failureReason());
        // 三种失败原因两两可区分
        assertNotEquals(revoked.failureReason(), RefreshFailureReason.IDLE_TIMEOUT);
        assertNotEquals(revoked.failureReason(), RefreshFailureReason.TOTAL_LIFETIME_REACHED);
    }

    @Test
    void idleTimeoutDoesNotRetroactivelyKillValidAccessToken() {
        // 闲置/总寿命只阻止刷新换发，不提前作废尚未过期的访问令牌
        String[] pair = sessionService.openSession("admin");
        assertTrue(sessionService.isSessionActive(pair[2]), "闲置不等于主动下线，会话仍标记活跃");
        clock.advance(Duration.ofMinutes(11));
        RefreshResult refresh = sessionService.rotate(pair[1]);
        assertEquals(RefreshFailureReason.IDLE_TIMEOUT, refresh.failureReason());
        assertTrue(sessionService.isSessionActive(pair[2]),
                "闲置超时不吊销会话族；只有下线/重用才让访问令牌立即失效");
    }
}
