package com.github.highcumontoa.gateway;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.auth.CredentialStore;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import com.github.highcumontoa.gateway.session.SessionInfo;
import com.github.highcumontoa.gateway.session.SessionRegistry;
import com.github.highcumontoa.gateway.support.MutableClock;
import com.github.highcumontoa.gateway.token.JwtService;
import com.github.highcumontoa.gateway.token.KeyManager;
import com.github.highcumontoa.gateway.token.RefreshFailureReason;
import com.github.highcumontoa.gateway.token.RefreshResult;
import com.github.highcumontoa.gateway.token.RefreshTokenService;
import com.github.highcumontoa.gateway.token.TokenFailureReason;
import com.github.highcumontoa.gateway.token.TokenValidationResult;
import com.github.highcumontoa.gateway.web.SessionController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;

/** 会话管理：活跃会话可见、单会话/全部下线、访问令牌立即失效且原因可区分、并发确定结果。 */
class SessionManagementTest {
    private static final Logger log = LoggerFactory.getLogger(SessionManagementTest.class);

    private GatewayProperties properties;
    private MutableClock clock;
    private SessionRegistry sessionRegistry;
    private JwtService jwtService;
    private RefreshTokenService refreshService;
    private SessionController sessionController;

    @BeforeEach
    void setUp() {
        properties = new GatewayProperties();
        clock = new MutableClock(Instant.parse("2026-10-07T00:00:00Z"));
        KeyManager keyManager = new KeyManager(properties, clock);
        sessionRegistry = new SessionRegistry(clock);
        jwtService = new JwtService(properties, keyManager, clock, sessionRegistry);
        AuditLog auditLog = new AuditLog(1000, clock);
        refreshService = new RefreshTokenService(properties, jwtService, new CredentialStore(), clock,
                sessionRegistry, auditLog);
        sessionController = new SessionController(jwtService, sessionRegistry, auditLog);
    }

    private String[] login(String username) {
        return refreshService.issueInitialTokenPair(username);
    }

    private static String bearer(String accessToken) {
        return "Bearer " + accessToken;
    }

    private String familyOf(String accessToken) {
        return jwtService.validate(accessToken).claims().sessionFamily();
    }

    @Test
    void listsActiveSessionsWithTimestampsAndStatusOnly() {
        String[] pair1 = login("alice");
        clock.advance(Duration.ofMinutes(10));
        String[] pair2 = login("alice");
        clock.advance(Duration.ofMinutes(5));
        // pair1 发生一次刷新轮换 -> 最近活动时间推进；pair2 不变
        RefreshResult rotated = refreshService.rotate(pair1[1]);
        assertTrue(rotated.isSuccess());

        @SuppressWarnings("unchecked")
        ResponseEntity<Map<String, Object>> response = (ResponseEntity<Map<String, Object>>)
                sessionController.listSessions(bearer(pair2[0]));
        assertEquals(HttpStatus.OK, response.getStatusCode());
        List<SessionInfo> sessions = (List<SessionInfo>) response.getBody().get("sessions");
        log.info("输入=alice两次登录+一次轮换, 判定依据=活跃会话列表按建立时间升序, 结论={}", sessions);
        assertEquals(2, sessions.size());
        SessionInfo first = sessions.get(0);
        SessionInfo second = sessions.get(1);
        assertEquals(Instant.parse("2026-10-07T00:00:00Z"), first.createdAt());
        assertEquals(Instant.parse("2026-10-07T00:15:00Z"), first.lastActivityAt(), "轮换应推进最近活动时间");
        assertEquals(Instant.parse("2026-10-07T00:10:00Z"), second.createdAt());
        assertEquals(Instant.parse("2026-10-07T00:10:00Z"), second.lastActivityAt(), "未活动的会话最近活动时间保持建立时刻");
        assertEquals(SessionInfo.Status.ACTIVE, first.status());
        assertEquals(SessionInfo.Status.ACTIVE, second.status());
        // 不暴露任何凭据
        String body = response.getBody().toString();
        assertFalse(body.contains(pair1[1]) || body.contains(pair2[1])
                || body.contains(pair1[0]) || body.contains(pair2[0]), "会话列表不得包含任何令牌");
    }

    @Test
    void terminateOneSessionRevokesItsAccessTokenImmediatelyWithDistinctReason() {
        String[] pair1 = login("alice");
        String[] pair2 = login("alice");
        String fam1 = familyOf(pair1[0]);
        assertTrue(jwtService.validate(pair1[0]).isValid());

        ResponseEntity<?> terminated = sessionController.terminateOne(bearer(pair2[0]), fam1);
        assertEquals(HttpStatus.NO_CONTENT, terminated.getStatusCode());

        TokenValidationResult after = jwtService.validate(pair1[0]);
        TokenValidationResult again = jwtService.validate(pair1[0]);
        log.info("输入=被下线会话的访问令牌, 判定依据=会话已吊销(签名/时效正常), 结论={} / 重复={}",
                after.failureReason(), again.failureReason());
        assertEquals(TokenFailureReason.SESSION_REVOKED, after.failureReason());
        assertEquals(TokenFailureReason.SESSION_REVOKED, again.failureReason(), "同一令牌重复请求结论必须一致");

        // 原因可区分：会话吊销 ≠ 令牌过期 ≠ 签名非法
        clock.advance(properties.getAccessTokenTtl().plus(properties.getClockSkewTolerance()).plusSeconds(1));
        TokenValidationResult expired = jwtService.validate(pair2[0]);
        log.info("输入=未下线会话的过期令牌, 判定依据=now>exp+skew, 结论={}", expired.failureReason());
        assertEquals(TokenFailureReason.EXPIRED, expired.failureReason());
        assertNotEquals(expired.failureReason(), after.failureReason());
        String tampered = pair1[0].substring(0, pair1[0].length() - 2) + "xx";
        assertEquals(TokenFailureReason.BAD_SIGNATURE, jwtService.validate(tampered).failureReason());
    }

    @Test
    void terminateOneDoesNotAffectOtherSessions() {
        String[] pair1 = login("alice");
        String[] pair2 = login("alice");
        sessionController.terminateOne(bearer(pair1[0]), familyOf(pair1[0]));

        assertTrue(jwtService.validate(pair2[0]).isValid(), "其他会话的访问令牌不受影响");
        RefreshResult rotated = refreshService.rotate(pair2[1]);
        log.info("输入=未下线会话的刷新令牌, 判定依据=会话仍活跃, 结论=success={}", rotated.isSuccess());
        assertTrue(rotated.isSuccess(), "其他会话的刷新令牌不受影响");
        // 被下线会话的刷新令牌不可再换发
        RefreshResult revoked = refreshService.rotate(pair1[1]);
        log.info("输入=被下线会话的刷新令牌, 判定依据=会话已吊销, 结论={}", revoked.failureReason());
        assertEquals(RefreshFailureReason.FAMILY_REVOKED, revoked.failureReason());
        // 他人会话不可被下线
        String[] bobs = login("bob");
        ResponseEntity<?> notFound = sessionController.terminateOne(bearer(bobs[0]), familyOf(pair2[0]));
        log.info("输入=bob尝试下线alice的会话, 判定依据=会话不属于当前主体, 结论={}", notFound.getStatusCode());
        assertEquals(HttpStatus.NOT_FOUND, notFound.getStatusCode());
        assertTrue(jwtService.validate(pair2[0]).isValid(), "他人操作不得影响本人会话");
    }

    @Test
    void terminateAllSessionsRevokesEveryTokenOfTheUser() {
        String[] pair1 = login("alice");
        String[] pair2 = login("alice");
        String[] bobs = login("bob");

        @SuppressWarnings("unchecked")
        ResponseEntity<Map<String, Object>> response = (ResponseEntity<Map<String, Object>>)
                sessionController.terminateAll(bearer(pair1[0]));
        assertEquals(HttpStatus.OK, response.getStatusCode());
        log.info("输入=alice全部下线, 判定依据=其全部活跃会话被吊销, 结论={}", response.getBody());
        assertEquals(2, ((Number) response.getBody().get("terminated")).intValue());

        assertEquals(TokenFailureReason.SESSION_REVOKED, jwtService.validate(pair1[0]).failureReason());
        assertEquals(TokenFailureReason.SESSION_REVOKED, jwtService.validate(pair2[0]).failureReason());
        assertEquals(RefreshFailureReason.FAMILY_REVOKED, refreshService.rotate(pair1[1]).failureReason());
        assertEquals(RefreshFailureReason.FAMILY_REVOKED, refreshService.rotate(pair2[1]).failureReason());
        assertTrue(jwtService.validate(bobs[0]).isValid(), "其他用户的会话不受影响");
        @SuppressWarnings("unchecked")
        List<SessionInfo> remaining = (List<SessionInfo>) ((Map<String, Object>)
                sessionController.listSessions(bearer(bobs[0])).getBody()).get("sessions");
        assertEquals(1, remaining.size(), "全部下线后 alice 不再有任何活跃会话可见（bob 仍有一个）");
    }

    @Test
    void concurrentTerminateAndRefreshHasDeterministicFinalState() throws InterruptedException {
        String[] pair = login("alice");
        String fam = familyOf(pair[0]);
        int refreshers = 8;
        ExecutorService pool = Executors.newFixedThreadPool(refreshers + 1);
        CountDownLatch ready = new CountDownLatch(refreshers + 1);
        CountDownLatch go = new CountDownLatch(1);
        ConcurrentLinkedQueue<RefreshResult> refreshes = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < refreshers; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    refreshes.add(refreshService.rotate(pair[1]));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        pool.submit(() -> {
            ready.countDown();
            try {
                go.await();
                sessionRegistry.revoke(fam);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        ready.await();
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        long successes = refreshes.stream().filter(RefreshResult::isSuccess).count();
        log.info("输入=下线与{}路并发刷新同时发生, 判定依据=CAS消耗+吊销原子迁移, 结论=刷新成功{}次", refreshers, successes);
        assertTrue(successes <= 1, "并发刷新至多一次成功");
        // 确定的最终状态：会话已吊销；无论刷新是否曾成功，该会话一切令牌立即不可用
        assertTrue(sessionRegistry.isRevoked(fam));
        assertEquals(TokenFailureReason.SESSION_REVOKED, jwtService.validate(pair[0]).failureReason());
        assertEquals(TokenFailureReason.SESSION_REVOKED, jwtService.validate(pair[0]).failureReason(), "重复判定一致");
        refreshes.stream().filter(RefreshResult::isSuccess).forEach(r ->
                assertEquals(TokenFailureReason.SESSION_REVOKED,
                        jwtService.validate(r.accessToken()).failureReason(),
                        "竞争中签出的新访问令牌同样立即失效"));
        assertEquals(RefreshFailureReason.FAMILY_REVOKED, refreshService.rotate(pair[1]).failureReason());
        assertEquals(RefreshFailureReason.FAMILY_REVOKED, refreshService.rotate(pair[1]).failureReason(), "重复刷新结论一致");
    }
}
