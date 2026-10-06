package com.github.highcumontoa.gateway;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.auth.CredentialStore;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import com.github.highcumontoa.gateway.policy.AccessDecision;
import com.github.highcumontoa.gateway.policy.Policy;
import com.github.highcumontoa.gateway.policy.PolicyEngine;
import com.github.highcumontoa.gateway.session.SessionRegistry;
import com.github.highcumontoa.gateway.support.MutableClock;
import com.github.highcumontoa.gateway.token.JwtService;
import com.github.highcumontoa.gateway.token.KeyManager;
import com.github.highcumontoa.gateway.token.RefreshTokenService;
import com.github.highcumontoa.gateway.web.ResourceController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;

class PolicyAndAuditTest {
    private static final Logger log = LoggerFactory.getLogger(PolicyAndAuditTest.class);

    private PolicyEngine policyEngine;
    private AuditLog auditLog;
    private ResourceController controller;
    private RefreshTokenService refreshService;

    @BeforeEach
    void setUp() {
        GatewayProperties properties = new GatewayProperties();
        MutableClock clock = new MutableClock(Instant.parse("2026-09-25T00:00:00Z"));
        KeyManager keyManager = new KeyManager(properties, clock);
        JwtService jwtService = new JwtService(properties, keyManager, clock);
        CredentialStore credentialStore = new CredentialStore();
        // 刷新服务使用独立审计日志，避免会话事件干扰资源访问审计的计数断言。
        refreshService = new RefreshTokenService(properties, jwtService, credentialStore, clock,
                new SessionRegistry(clock), new AuditLog());
        policyEngine = new PolicyEngine();
        auditLog = new AuditLog();
        controller = new ResourceController(jwtService, policyEngine, auditLog);
    }

    private String bearerFor(String username) {
        return "Bearer " + refreshService.issueInitialTokenPair(username)[0];
    }

    @Test
    void defaultDenyWhenNoPolicyMatches() {
        AccessDecision decision = policyEngine.evaluate(List.of("reader"), "documents", "write");
        log.info("输入=reader写documents, 判定依据={}, 结论={}", decision.reason(), decision.allowed());
        assertFalse(decision.allowed());

        decision = policyEngine.evaluate(List.of("reader"), "documents", "read");
        log.info("输入=reader读documents, 判定依据=命中{}, 结论={}", decision.matchedPolicies(), decision.allowed());
        assertTrue(decision.allowed());
    }

    @Test
    void policyChangeTakesEffectWithoutRestart() {
        String aliceToken = bearerFor("alice"); // 角色 reader

        ResponseEntity<?> before = controller.readDocuments(aliceToken);
        log.info("输入=alice(合法令牌,reader)读documents, 判定依据=策略变更前reader允许读, 结论={}", before.getStatusCode());
        assertEquals(HttpStatus.OK, before.getStatusCode());

        // 热更新：撤销 reader 的读权限（无需重启）
        policyEngine.replacePolicies(List.of(new Policy("writer", "documents", "write", true)));

        ResponseEntity<?> after = controller.readDocuments(aliceToken);
        log.info("输入=同一合法令牌再次访问, 判定依据=策略已变更reader不再允许读(默认拒绝), 结论={}", after.getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, after.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) after.getBody();
        log.info("拒绝原因可解释: {}", body.get("reason"));
        assertEquals("ACCESS_DENIED", body.get("error"));

        // 结论一致：同一令牌同一策略下重复请求结论相同
        assertEquals(HttpStatus.FORBIDDEN, controller.readDocuments(aliceToken).getStatusCode());
    }

    @Test
    void everyDecisionIsAudited() {
        String aliceToken = bearerFor("alice");
        controller.readDocuments(aliceToken);   // 允许
        controller.writeDocuments(aliceToken);  // 拒绝（reader 无写权限）

        assertEquals(2, auditLog.entries().size());
        var allowEntry = auditLog.entries().get(0);
        var denyEntry = auditLog.entries().get(1);
        log.info("审计[允许]: subject={} roles={} 依据={}", allowEntry.subject(), allowEntry.roles(), allowEntry.reason());
        log.info("审计[拒绝]: subject={} roles={} 依据={}", denyEntry.subject(), denyEntry.roles(), denyEntry.reason());
        assertTrue(allowEntry.allowed());
        assertFalse(denyEntry.allowed());
        assertEquals("alice", denyEntry.subject());
        assertFalse(denyEntry.reason().isBlank(), "拒绝必须留下可追溯的判定依据");
    }

    @Test
    void roleInjectionViaTokenRequestIsImpossible() {
        // 角色只能来自服务端用户档案：alice 的令牌角色由 CredentialStore 决定
        String token = refreshService.issueInitialTokenPair("alice")[0];
        ResponseEntity<?> response = controller.writeDocuments("Bearer " + token);
        log.info("输入=alice(reader)尝试写documents, 判定依据=角色来自服务端档案[reader]而非客户端声明, 结论={}",
                response.getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
    }

    @Test
    void tamperedRoleClaimRejected() throws Exception {
        // 越权声明：把 reader 篡改为 admin，签名必然失效
        String token = refreshService.issueInitialTokenPair("alice")[0];
        String[] parts = token.split("\\.");
        String forgedPayload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]))
                .replace("reader", "admin");
        String tampered = parts[0] + "."
                + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(forgedPayload.getBytes())
                + "." + parts[2];
        ResponseEntity<?> response = controller.readDocuments("Bearer " + tampered);
        log.info("输入=篡改roles为admin的令牌, 判定依据=签名与内容不匹配(BAD_SIGNATURE), 结论={}", response.getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertEquals("BAD_SIGNATURE", body.get("error"));
    }
}
