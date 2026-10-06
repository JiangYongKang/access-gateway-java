package com.github.highcumontoa.gateway;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.auth.CredentialStore;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import com.github.highcumontoa.gateway.policy.PolicyEngine;
import com.github.highcumontoa.gateway.session.SessionInfo;
import com.github.highcumontoa.gateway.session.SessionService;
import com.github.highcumontoa.gateway.session.SessionState;
import com.github.highcumontoa.gateway.support.MutableClock;
import com.github.highcumontoa.gateway.token.JwtService;
import com.github.highcumontoa.gateway.token.KeyManager;
import com.github.highcumontoa.gateway.token.TokenFailureReason;
import com.github.highcumontoa.gateway.token.TokenValidationResult;
import com.github.highcumontoa.gateway.web.ResourceController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;

/** 会话管理：列举、单会话下线、全部下线、访问令牌即时失效与会话隔离。 */
class SessionManagementTest {
    private static final Logger log = LoggerFactory.getLogger(SessionManagementTest.class);

    private GatewayProperties properties;
    private MutableClock clock;
    private SessionService sessionService;
    private JwtService jwtService;
    private AuditLog auditLog;
    private ResourceController controller;

    @BeforeEach
    void setUp() {
        properties = new GatewayProperties();
        clock = new MutableClock(Instant.parse("2026-10-01T00:00:00Z"));
        KeyManager keyManager = new KeyManager(properties, clock);
        jwtService = new JwtService(properties, keyManager, clock);
        CredentialStore credentialStore = new CredentialStore();
        auditLog = new AuditLog(properties);
        sessionService = new SessionService(properties, clock, auditLog, jwtService, credentialStore);
        controller = new ResourceController(jwtService, new PolicyEngine(), auditLog, sessionService);
    }

    @Test
    void listSessionsShowsMetadataWithoutCredentials() {
        String[] s1 = sessionService.openSession("alice");
        clock.advance(java.time.Duration.ofMinutes(5));
        String[] s2 = sessionService.openSession("alice");

        List<SessionInfo> sessions = sessionService.listSessions("alice");
        log.info("输入=列举alice会话, 判定依据=返回建立时间/最近活动/状态且不含凭据, 结论=数量{} 状态{}/{}",
                sessions.size(), sessions.get(0).state(), sessions.get(1).state());
        assertEquals(2, sessions.size());
        assertEquals(SessionState.ACTIVE, sessions.get(0).state());
        assertEquals(SessionState.ACTIVE, sessions.get(1).state());
        assertTrue(sessions.get(1).lastActivityAt().isAfter(sessions.get(0).createdAt()));
        for (SessionInfo info : sessions) {
            assertEquals("alice", info.subject());
            assertNotNull(info.sessionId());
            assertNotNull(info.createdAt());
        }
        // 返回的 triple 与列表不泄露刷新令牌：列表里没有任何字段能等于刷新令牌
        assertNotEquals(s1[1], sessions.get(0).sessionId());
        assertNotEquals(s2[1], sessions.get(1).sessionId());
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> body(ResponseEntity<?> resp) {
        return (Map<String, Object>) resp.getBody();
    }

    @Test
    void terminateOneSessionKillsItsAccessTokenImmediately() {
        String[] session = sessionService.openSession("bob");
        String familyId = session[2];
        String bearer = "Bearer " + session[0];

        // 下线前：令牌签名/时效正常，访问成功
        ResponseEntity<?> before = controller.readDocuments(bearer);
        log.info("输入=下线前携带会话令牌访问, 判定依据=令牌合法且会话活跃, 结论={}", before.getStatusCode());
        assertEquals(HttpStatus.OK, before.getStatusCode());

        // 主动下线该会话
        assertNull(sessionService.terminate("bob", familyId));

        // 下线后：令牌仍合法（签名/时效正常），但立即 401 且原因是 SESSION_REVOKED
        ResponseEntity<?> after = controller.readDocuments(bearer);
        log.info("输入=下线后携带同一会话令牌访问, 判定依据=会话已终止, 结论={} error={}",
                after.getStatusCode(), body(after).get("error"));
        assertEquals(HttpStatus.UNAUTHORIZED, after.getStatusCode());
        assertEquals(TokenFailureReason.SESSION_REVOKED.name(), body(after).get("error"));

        // 同一条令牌重复请求结论一致
        ResponseEntity<?> again = controller.readDocuments(bearer);
        assertEquals(HttpStatus.UNAUTHORIZED, again.getStatusCode());
        assertEquals(TokenFailureReason.SESSION_REVOKED.name(), body(again).get("error"));

        // 与令牌自身非法/过期/签发方不匹配可区分：直接验签仍然有效
        TokenValidationResult validation = jwtService.validate(session[0]);
        assertTrue(validation.isValid(), "令牌本身仍在有效期内，失效仅源于会话下线");

        // 会话状态变为 TERMINATED
        assertEquals(SessionState.TERMINATED,
                sessionService.listSessions("bob").stream()
                        .filter(i -> i.sessionId().equals(familyId)).findFirst().orElseThrow().state());
    }

    @Test
    void sessionsAreIsolatedUnlessTerminateAll() {
        String[] a = sessionService.openSession("alice");
        String[] b = sessionService.openSession("alice");

        sessionService.terminate("alice", a[2]);

        ResponseEntity<?> aResp = controller.readDocuments("Bearer " + a[0]);
        ResponseEntity<?> bResp = controller.readDocuments("Bearer " + b[0]);
        log.info("输入=下线会话A后分别访问A/B, 判定依据=会话之间互不影响, 结论=A:{} B:{}",
                body(aResp).get("error"), bResp.getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED, aResp.getStatusCode());
        assertEquals(TokenFailureReason.SESSION_REVOKED.name(), body(aResp).get("error"));
        assertEquals(HttpStatus.OK, bResp.getStatusCode(), "未被下线的会话必须继续可用");
    }

    @Test
    void terminateAllKillsOnlyAllSessionsOfSameSubject() {
        String[] alice1 = sessionService.openSession("alice");
        String[] alice2 = sessionService.openSession("alice");
        String[] bob = sessionService.openSession("bob");

        int terminated = sessionService.terminateAll("alice");
        log.info("输入=alice全部下线, 判定依据=仅终止alice的会话, 结论=终止数{}", terminated);
        assertEquals(2, terminated);

        assertEquals(HttpStatus.UNAUTHORIZED,
                controller.readDocuments("Bearer " + alice1[0]).getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED,
                controller.readDocuments("Bearer " + alice2[0]).getStatusCode());
        // 其他主体的会话不受影响
        assertEquals(HttpStatus.OK,
                controller.readDocuments("Bearer " + bob[0]).getStatusCode());

        // 全部下线幂等：再次调用终止数为 0，bob 依旧可用
        assertEquals(0, sessionService.terminateAll("alice"));
        assertEquals(HttpStatus.OK,
                controller.readDocuments("Bearer " + bob[0]).getStatusCode());
    }

    @Test
    void cannotTerminateSessionOwnedByAnotherSubject() {
        String[] alice = sessionService.openSession("alice");
        String[] bob = sessionService.openSession("bob");
        // bob 尝试下线 alice 的会话：被拒绝，alice 会话仍活跃
        var reason = sessionService.terminate("bob", alice[2]);
        log.info("输入=bob尝试下线alice的会话, 判定依据=归属校验, 结论={}", reason);
        assertNotNull(reason);
        assertEquals(HttpStatus.OK,
                controller.readDocuments("Bearer " + alice[0]).getStatusCode());
        // 未知会话 id
        assertNotNull(sessionService.terminate("bob", "no-such-session"));
        // bob 自己的会话不受影响
        assertEquals(HttpStatus.OK,
                controller.readDocuments("Bearer " + bob[0]).getStatusCode());
    }
}
