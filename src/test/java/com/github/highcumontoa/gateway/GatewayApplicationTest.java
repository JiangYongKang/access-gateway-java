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
}
