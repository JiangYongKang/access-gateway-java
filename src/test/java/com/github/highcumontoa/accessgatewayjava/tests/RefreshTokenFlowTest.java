package com.github.highcumontoa.accessgatewayjava.tests;

import com.github.highcumontoa.accessgatewayjava.auth.AuthError;
import com.github.highcumontoa.accessgatewayjava.auth.AuthException;
import com.github.highcumontoa.accessgatewayjava.auth.IssuedTokens;
import com.github.highcumontoa.accessgatewayjava.tests.support.TestGateway;
import com.github.highcumontoa.accessgatewayjava.token.TokenException;
import com.github.highcumontoa.accessgatewayjava.token.TokenRejectReason;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 刷新令牌：轮换、并发唯一成功、重用检测与吊销。
 * 每个用例打印输入与判定依据。
 */
class RefreshTokenFlowTest {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenFlowTest.class);

    @Test
    void wrongCredentialsRejected() {
        TestGateway gw = TestGateway.create();
        log.info("输入: 用户 alice 错误密码");
        AuthException ex = assertThrows(AuthException.class,
                () -> gw.auth.login("alice", "wrong-pass", "demo-api"));
        log.info("判定依据: error={} message={}", ex.getError(), ex.getMessage());
        assertEquals(AuthError.INVALID_CREDENTIALS, ex.getError());
    }

    @Test
    void refreshRotatesAndOldTokenReuseRevokesFamily() {
        TestGateway gw = TestGateway.create();
        IssuedTokens first = gw.auth.login("bob", "bob-pass", "demo-api");
        log.info("输入: bob 登录，familyId={}", first.familyId());

        IssuedTokens second = gw.auth.refresh(first.refreshToken());
        log.info("判定依据: 首次刷新成功，轮换出新刷新令牌");

        AuthException reused = assertThrows(AuthException.class,
                () -> gw.auth.refresh(first.refreshToken()));
        log.info("判定依据: 旧刷新令牌再次使用 error={} message={}", reused.getError(), reused.getMessage());
        assertEquals(AuthError.REFRESH_TOKEN_REUSED, reused.getError());

        AuthException revoked = assertThrows(AuthException.class,
                () -> gw.auth.refresh(second.refreshToken()));
        log.info("判定依据: 重用后新令牌亦不可用（族不可恢复） error={} message={}",
                revoked.getError(), revoked.getMessage());
        assertEquals(AuthError.REFRESH_TOKEN_REVOKED, revoked.getError());

        var family = gw.sessions.listFamilies().stream()
                .filter(f -> f.getFamilyId().equals(first.familyId())).findFirst().orElseThrow();
        assertTrue(family.isRevoked());
        assertTrue(family.getRevokeReason().startsWith("reuse-detected"));
        log.info("判定依据: 会话族状态 revoked={} reason={}", family.isRevoked(), family.getRevokeReason());
    }

    @Test
    void concurrentRefreshExactlyOneSucceeds() throws Exception {
        TestGateway gw = TestGateway.create();
        IssuedTokens first = gw.auth.login("carol", "carol-pass", "demo-api");
        int threads = 16;
        log.info("输入: carol 登录后，{} 个线程并发使用同一刷新令牌 familyId={}", threads, first.familyId());

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<String>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await(5, TimeUnit.SECONDS);
                try {
                    gw.auth.refresh(first.refreshToken());
                    return "thread-" + idx + ": SUCCESS";
                } catch (AuthException e) {
                    return "thread-" + idx + ": " + e.getError();
                }
            }));
        }
        assertTrue(ready.await(5, TimeUnit.SECONDS));
        start.countDown();

        List<String> results = new ArrayList<>();
        for (Future<String> f : futures) {
            results.add(f.get(10, TimeUnit.SECONDS));
        }
        pool.shutdown();
        results.forEach(r -> log.info("判定依据: {}", r));

        long successes = results.stream().filter(r -> r.endsWith("SUCCESS")).count();
        long reuseOrRevoked = results.stream()
                .filter(r -> r.endsWith("REFRESH_TOKEN_REUSED") || r.endsWith("REFRESH_TOKEN_REVOKED"))
                .count();
        log.info("判定依据: 成功数={} 重用/吊销失败数={}", successes, reuseOrRevoked);
        assertEquals(1, successes, "同一刷新令牌并发使用必须有且仅有一次成功");
        assertEquals(threads - 1, reuseOrRevoked);

        var family = gw.sessions.listFamilies().stream()
                .filter(f -> f.getFamilyId().equals(first.familyId())).findFirst().orElseThrow();
        assertTrue(family.isRevoked(), "并发重用检测后会话族必须被吊销且不可恢复");
        log.info("判定依据: 会话族最终状态 revoked={} reason={}", family.isRevoked(), family.getRevokeReason());
    }

    @Test
    void explicitlyRevokedFamilyCannotRefresh() {
        TestGateway gw = TestGateway.create();
        IssuedTokens tokens = gw.auth.login("alice", "alice-pass", "demo-api");
        log.info("输入: alice 登录后显式吊销 familyId={}", tokens.familyId());
        assertTrue(gw.auth.revoke(tokens.familyId()));

        AuthException ex = assertThrows(AuthException.class,
                () -> gw.auth.refresh(tokens.refreshToken()));
        log.info("判定依据: error={} message={}", ex.getError(), ex.getMessage());
        assertEquals(AuthError.REFRESH_TOKEN_REVOKED, ex.getError());
    }

    @Test
    void expiredRefreshTokenRejected() {
        TestGateway gw = TestGateway.create();
        IssuedTokens tokens = gw.auth.login("alice", "alice-pass", "demo-api");
        long skew = gw.props.getToken().getClockSkewSeconds();
        gw.clock.advance(Duration.ofSeconds(gw.props.getToken().getRefreshTtlSeconds() + skew + 1));
        log.info("输入: 时钟推进超过 refreshTtl+skew={}s 后使用刷新令牌",
                gw.props.getToken().getRefreshTtlSeconds() + skew + 1);

        TokenException ex = assertThrows(TokenException.class,
                () -> gw.auth.refresh(tokens.refreshToken()));
        log.info("判定依据: reason={} message={}", ex.getReason(), ex.getMessage());
        assertEquals(TokenRejectReason.EXPIRED, ex.getReason());
    }
}
