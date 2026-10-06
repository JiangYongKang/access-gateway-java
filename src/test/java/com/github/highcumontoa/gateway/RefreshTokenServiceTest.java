package com.github.highcumontoa.gateway;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import com.github.highcumontoa.gateway.auth.CredentialStore;
import com.github.highcumontoa.gateway.audit.AuditLog;
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

class RefreshTokenServiceTest {
    private static final Logger log = LoggerFactory.getLogger(RefreshTokenServiceTest.class);

    private GatewayProperties properties;
    private MutableClock clock;
    private RefreshTokenService refreshService;

    @BeforeEach
    void setUp() {
        properties = new GatewayProperties();
        clock = new MutableClock(Instant.parse("2026-09-25T00:00:00Z"));
        KeyManager keyManager = new KeyManager(properties, clock);
        JwtService jwtService = new JwtService(properties, keyManager, clock);
        refreshService = new RefreshTokenService(properties, jwtService, new CredentialStore(), clock,
                new SessionRegistry(clock), new AuditLog());
    }

    @Test
    void rotationIssuesNewPairAndInvalidatesOld() {
        String[] pair = refreshService.issueInitialTokenPair("alice");
        RefreshResult first = refreshService.rotate(pair[1]);
        log.info("输入=首次刷新, 判定依据=令牌未使用且未过期, 结论=success={}", first.isSuccess());
        assertTrue(first.isSuccess());

        RefreshResult reuse = refreshService.rotate(pair[1]);
        log.info("输入=重复使用旧刷新令牌, 判定依据=令牌已消耗触发重用检测并吊销会话族, 结论={}", reuse.failureReason());
        assertEquals(RefreshFailureReason.ALREADY_USED_REUSE_DETECTED, reuse.failureReason());

        // 会话族被吊销后，连合法轮换出的新令牌也不可用，且不可恢复
        RefreshResult afterRevoke = refreshService.rotate(first.refreshToken());
        log.info("输入=重用检测后使用新令牌, 判定依据=会话族已吊销, 结论={}", afterRevoke.failureReason());
        assertEquals(RefreshFailureReason.FAMILY_REVOKED, afterRevoke.failureReason());
        assertTrue(refreshService.isFamilyRevoked(pair[1]));
    }

    @Test
    void concurrentRefreshExactlyOneSucceeds() throws InterruptedException {
        String[] pair = refreshService.issueInitialTokenPair("bob");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        ConcurrentLinkedQueue<RefreshResult> results = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    results.add(refreshService.rotate(pair[1]));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        ready.await();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        long successes = results.stream().filter(RefreshResult::isSuccess).count();
        long reuseDetected = results.stream()
                .filter(r -> r.failureReason() == RefreshFailureReason.ALREADY_USED_REUSE_DETECTED).count();
        long familyRevoked = results.stream()
                .filter(r -> r.failureReason() == RefreshFailureReason.FAMILY_REVOKED).count();
        log.info("输入={}个线程并发刷新同一令牌, 判定依据=CAS原子消耗仅一次成功, 其余因重用检测或族吊销失败, 结论=成功{}次/重用{}次/族吊销{}次/总计{}",
                threads, successes, reuseDetected, familyRevoked, results.size());
        assertEquals(threads, results.size());
        assertEquals(1, successes, "并发刷新必须有且仅有一次成功");
        assertEquals(threads - 1, reuseDetected + familyRevoked, "其余线程必须全部失败且原因可区分");
        assertTrue(refreshService.isFamilyRevoked(pair[1]), "检测到重用后会话族必须被吊销");
    }

    @Test
    void explicitRevocationRejectsFurtherUse() {
        String[] pair = refreshService.issueInitialTokenPair("alice");
        refreshService.revokeFamily(pair[1]);
        RefreshResult result = refreshService.rotate(pair[1]);
        log.info("输入=显式吊销后刷新, 判定依据=会话族已吊销, 结论={}", result.failureReason());
        assertEquals(RefreshFailureReason.FAMILY_REVOKED, result.failureReason());
    }

    @Test
    void expiredRefreshTokenRejected() {
        String[] pair = refreshService.issueInitialTokenPair("alice");
        clock.advance(properties.getRefreshTokenTtl().plus(Duration.ofSeconds(1)));
        RefreshResult result = refreshService.rotate(pair[1]);
        log.info("输入=过期刷新令牌, 判定依据=now>exp, 结论={}", result.failureReason());
        assertEquals(RefreshFailureReason.EXPIRED, result.failureReason());
    }

    @Test
    void unknownRefreshTokenRejected() {
        RefreshResult result = refreshService.rotate("does-not-exist");
        log.info("输入=未知刷新令牌, 判定依据=令牌不存在, 结论={}", result.failureReason());
        assertEquals(RefreshFailureReason.UNKNOWN_TOKEN, result.failureReason());
    }

    @Test
    void normalRotationChainWorks() {
        String[] pair = refreshService.issueInitialTokenPair("admin");
        String current = pair[1];
        for (int i = 0; i < 3; i++) {
            RefreshResult result = refreshService.rotate(current);
            assertTrue(result.isSuccess(), "第 " + i + " 次轮换应成功");
            current = result.refreshToken();
        }
        log.info("输入=连续3次正常轮换, 判定依据=每次消耗旧令牌签发新令牌, 结论=全部成功");
    }
}
