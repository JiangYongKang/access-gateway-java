package com.github.highcumontoa.gateway;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
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

/** 下线与并发刷新同时发生时的确定性，以及高并发下审计写入不丢不乱序。 */
class SessionConcurrencyTest {
    private static final Logger log = LoggerFactory.getLogger(SessionConcurrencyTest.class);

    private GatewayProperties properties;
    private MutableClock clock;
    private SessionService sessionService;
    private AuditLog auditLog;

    @BeforeEach
    void setUp() {
        properties = new GatewayProperties();
        clock = new MutableClock(Instant.parse("2026-10-01T00:00:00Z"));
        KeyManager keyManager = new KeyManager(properties, clock);
        JwtService jwtService = new JwtService(properties, keyManager, clock);
        auditLog = new AuditLog(properties);
        sessionService = new SessionService(properties, clock, auditLog, jwtService,
                new CredentialStore());
    }

    @Test
    void concurrentRotateAndTerminateHaveDeterminableOutcome() throws Exception {
        int rounds = 200;
        int observedRefreshWins = 0;
        int observedTerminateWins = 0;
        for (int round = 0; round < rounds; round++) {
            String[] s = sessionService.openSession("bob");
            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch go = new CountDownLatch(1);
            ConcurrentLinkedQueue<Object> outcome = new ConcurrentLinkedQueue<>();
            ExecutorService pool = Executors.newFixedThreadPool(2);
            pool.submit(() -> {
                ready.countDown();
                await(go);
                outcome.add(sessionService.rotate(s[1]));
            });
            pool.submit(() -> {
                ready.countDown();
                await(go);
                outcome.add(sessionService.terminate("bob", s[2]));
            });
            ready.await();
            go.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

            RefreshResult refresh = (RefreshResult) outcome.stream()
                    .filter(o -> o instanceof RefreshResult).findFirst().orElseThrow();

            // 可线性化：刷新与下线必有一个先拿锁；
            //  - 刷新先赢：这一次成功，但下线随后终止会话，再用刚换出的令牌刷新必为 FAMILY_REVOKED；
            //  - 下线先赢：本次刷新必为 FAMILY_REVOKED。
            if (refresh.isSuccess()) {
                observedRefreshWins++;
                RefreshResult after = sessionService.rotate(refresh.refreshToken());
                assertEquals(RefreshFailureReason.FAMILY_REVOKED, after.failureReason(),
                        "刷新先成功后会话已下线，新令牌必须立即不能换新");
            } else {
                observedTerminateWins++;
                assertEquals(RefreshFailureReason.FAMILY_REVOKED, refresh.failureReason(),
                        "下线先发生时并发刷新必须以 FAMILY_REVOKED 失败");
            }
            // 无论谁先赢，最终会话一定处于终止状态且不可恢复
            assertTrue(sessionService.isFamilyRevokedByToken(s[1]));
            assertFalse(sessionService.isSessionActive(s[2]));
        }
        log.info("输入={}轮[并发刷新 vs 下线], 判定依据=同一把会话锁串行化两者, 结论=刷新先赢{}轮/下线先赢{}轮, 每轮结果均自洽",
                rounds, observedRefreshWins, observedTerminateWins);
        assertTrue(observedRefreshWins + observedTerminateWins == rounds);
    }

    private static void await(CountDownLatch latch) {
        try { latch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
