package com.github.highcumontoa.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** 端到端冒烟：真实 HTTP 走通 凭证->令牌->访问->刷新 全流程。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GatewayApplicationTest {
    @Autowired
    private TestRestTemplate rest;

    @Test
    void fullFlowOverHttp() {
        // 1. 错误凭证被拒绝
        ResponseEntity<Map> badCred = rest.postForEntity("/auth/token",
                Map.of("username", "alice", "password", "wrong"), Map.class);
        assertEquals(401, badCred.getStatusCode().value());
        assertEquals("INVALID_CREDENTIALS", badCred.getBody().get("error"));

        // 2. 正确凭证签发令牌
        ResponseEntity<Map> tokenResp = rest.postForEntity("/auth/token",
                Map.of("username", "bob", "password", "bob-pass"), Map.class);
        assertEquals(200, tokenResp.getStatusCode().value());
        String accessToken = (String) tokenResp.getBody().get("accessToken");
        String refreshToken = (String) tokenResp.getBody().get("refreshToken");

        // 3. 携带令牌访问受保护资源（bob 有 writer 角色）
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        ResponseEntity<Map> write = rest.exchange("/api/documents",
                org.springframework.http.HttpMethod.POST, new HttpEntity<>(headers), Map.class);
        assertEquals(200, write.getStatusCode().value());

        // 4. 刷新轮换
        ResponseEntity<Map> refresh = rest.postForEntity("/auth/refresh",
                Map.of("refreshToken", refreshToken), Map.class);
        assertEquals(200, refresh.getStatusCode().value());

        // 5. 旧刷新令牌重用被检测
        ResponseEntity<Map> reuse = rest.postForEntity("/auth/refresh",
                Map.of("refreshToken", refreshToken), Map.class);
        assertEquals(403, reuse.getStatusCode().value());
        assertEquals("ALREADY_USED_REUSE_DETECTED", reuse.getBody().get("error"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void sessionManagementOverHttp() {
        // alice 建立两个会话
        ResponseEntity<Map> login1 = rest.postForEntity("/auth/token",
                Map.of("username", "alice", "password", "alice-pass"), Map.class);
        assertEquals(200, login1.getStatusCode().value());
        String token1 = (String) login1.getBody().get("accessToken");
        String rt1 = (String) login1.getBody().get("refreshToken");

        ResponseEntity<Map> login2 = rest.postForEntity("/auth/token",
                Map.of("username", "alice", "password", "alice-pass"), Map.class);
        assertEquals(200, login2.getStatusCode().value());
        String token2 = (String) login2.getBody().get("accessToken");

        // 1. 列举会话：能看到元数据，且响应中不出现刷新令牌原文
        HttpHeaders listHeaders = new HttpHeaders();
        listHeaders.setBearerAuth(token1);
        ResponseEntity<Map> listResp = rest.exchange("/auth/sessions",
                org.springframework.http.HttpMethod.GET, new HttpEntity<>(listHeaders), Map.class);
        assertEquals(200, listResp.getStatusCode().value());
        java.util.List<java.util.Map<String, Object>> sessions =
                (java.util.List<java.util.Map<String, Object>>) listResp.getBody().get("sessions");
        assertEquals(2, sessions.size());
        for (java.util.Map<String, Object> s : sessions) {
            assertNotNull(s.get("sessionId"));
            assertNotNull(s.get("createdAt"));
            assertNotNull(s.get("lastActivityAt"));
            assertEquals("ACTIVE", s.get("state"));
        }
        String family1 = (String) sessions.get(0).get("sessionId");
        String family2 = (String) sessions.get(1).get("sessionId");
        assertFalse(listResp.toString().contains(rt1), "会话列表不得暴露刷新令牌");

        // 2. 下线其中一个会话
        HttpHeaders terminateHeaders = new HttpHeaders();
        terminateHeaders.setBearerAuth(token1);
        ResponseEntity<Map> terminated = rest.exchange("/auth/sessions/" + family1 + "/terminate",
                org.springframework.http.HttpMethod.POST, new HttpEntity<>(terminateHeaders), Map.class);
        assertEquals(204, terminated.getStatusCode().value());

        // 3. 被下线会话的访问令牌（签名/时效正常）立即 401 且原因可区分
        HttpHeaders revokedHeaders = new HttpHeaders();
        revokedHeaders.setBearerAuth(token1);
        ResponseEntity<Map> revoked = rest.exchange("/api/documents",
                org.springframework.http.HttpMethod.GET, new HttpEntity<>(revokedHeaders), Map.class);
        assertEquals(401, revoked.getStatusCode().value());
        assertEquals("SESSION_REVOKED", revoked.getBody().get("error"));

        // 另一个会话不受影响
        HttpHeaders aliveHeaders = new HttpHeaders();
        aliveHeaders.setBearerAuth(token2);
        ResponseEntity<Map> alive = rest.exchange("/api/documents",
                org.springframework.http.HttpMethod.GET, new HttpEntity<>(aliveHeaders), Map.class);
        assertEquals(200, alive.getStatusCode().value());

        // 4. 被下线会话的刷新令牌也不能换新
        ResponseEntity<Map> refreshAfter = rest.postForEntity("/auth/refresh",
                Map.of("refreshToken", rt1), Map.class);
        assertEquals(403, refreshAfter.getStatusCode().value());
        assertEquals("FAMILY_REVOKED", refreshAfter.getBody().get("error"));

        // 5. 全部下线：token2 也立即失效
        HttpHeaders allHeaders = new HttpHeaders();
        allHeaders.setBearerAuth(token2);
        ResponseEntity<Map> allResp = rest.exchange("/auth/sessions/terminate-all",
                org.springframework.http.HttpMethod.POST, new HttpEntity<>(allHeaders), Map.class);
        assertEquals(200, allResp.getStatusCode().value());
        HttpHeaders revoked2Headers = new HttpHeaders();
        revoked2Headers.setBearerAuth(token2);
        ResponseEntity<Map> revoked2 = rest.exchange("/api/documents",
                org.springframework.http.HttpMethod.GET, new HttpEntity<>(revoked2Headers), Map.class);
        assertEquals(401, revoked2.getStatusCode().value());
        assertEquals("SESSION_REVOKED", revoked2.getBody().get("error"));

        // 6. 审计可按主体与动作筛选，且下线事件在列
        ResponseEntity<java.util.List> audit = rest.getForEntity(
                "/admin/audit?subject=alice&action=SESSION_TERMINATED", java.util.List.class);
        assertEquals(200, audit.getStatusCode().value());
        assertNotNull(audit.getBody());
        assertTrue(audit.getBody().size() >= 1, "主动下线必须进入审计");
    }
}
