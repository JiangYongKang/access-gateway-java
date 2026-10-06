package com.github.highcumontoa.gateway;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;

/** 端到端：真实 HTTP 走通 登录x2 -> 会话列表 -> 单会话下线 -> 立即失效 -> 审计可查。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SessionEndpointsHttpTest {
    private static final Logger log = LoggerFactory.getLogger(SessionEndpointsHttpTest.class);

    @Autowired
    private TestRestTemplate rest;

    @Test
    void sessionLifecycleOverHttp() {
        // 同一用户两次登录 -> 两个会话
        String token1 = login();
        String token2 = login();

        HttpHeaders h1 = bearer(token1);
        ResponseEntity<Map> list = rest.exchange("/auth/sessions", HttpMethod.GET,
                new HttpEntity<>(h1), Map.class);
        assertEquals(200, list.getStatusCode().value());
        List<Map<String, Object>> sessions = (List<Map<String, Object>>) list.getBody().get("sessions");
        log.info("输入=两次登录后查询会话, 判定依据=活跃会话2个且不含凭据, 结论={}", sessions);
        assertEquals(2, sessions.size());
        assertTrue(sessions.stream().allMatch(s -> s.containsKey("createdAt")
                && s.containsKey("lastActivityAt") && "ACTIVE".equals(s.get("status"))));
        String victimSession = (String) sessions.get(0).get("sessionId");
        String otherSession = (String) sessions.get(1).get("sessionId");

        // 下线其中一个会话
        ResponseEntity<Void> del = rest.exchange("/auth/sessions/" + victimSession, HttpMethod.DELETE,
                new HttpEntity<>(h1), Void.class);
        assertEquals(204, del.getStatusCode().value());

        // 属于被下线会话的访问令牌立即失效，原因可区分
        // （victim 会话对应哪个令牌不确定，两个令牌中恰有一个失效）
        ResponseEntity<Map> r1 = rest.exchange("/api/documents", HttpMethod.GET,
                new HttpEntity<>(bearer(token1)), Map.class);
        ResponseEntity<Map> r2 = rest.exchange("/api/documents", HttpMethod.GET,
                new HttpEntity<>(bearer(token2)), Map.class);
        log.info("输入=下线后两个访问令牌分别请求, 判定依据=被下线会话的令牌SESSION_REVOKED, 结论={} / {}",
                r1.getBody(), r2.getBody());
        int revoked = 0;
        int ok = 0;
        for (ResponseEntity<Map> r : List.of(r1, r2)) {
            if (r.getStatusCode().value() == 401
                    && "SESSION_REVOKED".equals(r.getBody().get("error"))) {
                revoked++;
            } else if (r.getStatusCode().value() == 200) {
                ok++;
            }
        }
        assertEquals(1, revoked, "恰有一个令牌因会话下线被拒绝");
        assertEquals(1, ok, "另一会话不受影响");

        // 审计可按事件类型与结论筛选
        ResponseEntity<List> audit = rest.getForEntity(
                "/admin/audit?eventType=SESSION_TERMINATED&allowed=true", List.class);
        log.info("输入=按eventType筛选审计, 判定依据=下线动作已留痕, 结论={}", audit.getBody());
        assertEquals(200, audit.getStatusCode().value());
        assertFalse(audit.getBody().isEmpty(), "下线动作必须进入审计");
        assertTrue(((Map<?, ?>) audit.getBody().get(0)).get("sessionId").equals(victimSession));

        // 全部下线：剩余会话也被吊销
        ResponseEntity<Map> delAll = rest.exchange("/auth/sessions", HttpMethod.DELETE,
                new HttpEntity<>(bearer(token1)), Map.class);
        // 注意：token1 可能已失效（若它属于 victim 会话），则用 token2
        if (delAll.getStatusCode().value() != 200) {
            delAll = rest.exchange("/auth/sessions", HttpMethod.DELETE,
                    new HttpEntity<>(bearer(token2)), Map.class);
        }
        assertEquals(200, delAll.getStatusCode().value());
        log.info("输入=全部下线, 判定依据=该用户所有会话吊销, 结论={}", delAll.getBody());
        ResponseEntity<Map> afterAll = rest.exchange("/api/documents", HttpMethod.GET,
                new HttpEntity<>(bearer(token1)), Map.class);
        ResponseEntity<Map> afterAll2 = rest.exchange("/api/documents", HttpMethod.GET,
                new HttpEntity<>(bearer(token2)), Map.class);
        assertEquals("SESSION_REVOKED", afterAll.getBody().get("error"));
        assertEquals("SESSION_REVOKED", afterAll2.getBody().get("error"));
    }

    private String login() {
        ResponseEntity<Map> resp = rest.postForEntity("/auth/token",
                Map.of("username", "alice", "password", "alice-pass"), Map.class);
        assertEquals(200, resp.getStatusCode().value());
        return (String) resp.getBody().get("accessToken");
    }

    private static HttpHeaders bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return headers;
    }
}
