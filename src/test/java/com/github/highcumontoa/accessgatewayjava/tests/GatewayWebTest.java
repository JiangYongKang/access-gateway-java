package com.github.highcumontoa.accessgatewayjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端：登录 → 访问判定 → 策略热更新 → 审计追溯；
 * 角色注入与令牌篡改等伪造尝试必须被拒绝。
 */
@SpringBootTest
@AutoConfigureMockMvc
class GatewayWebTest {

    private static final Logger log = LoggerFactory.getLogger(GatewayWebTest.class);

    @Autowired
    private MockMvc mvc;

    private final ObjectMapper mapper = new ObjectMapper();

    private String login(String username, String password, Map<String, Object> extra) throws Exception {
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("username", username);
        body.put("password", password);
        body.putAll(extra);
        log.info("输入: POST /auth/login body={}", body);
        MvcResult result = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
        log.info("判定依据: 登录成功 familyId={} tokenType={}", json.get("familyId"), json.get("tokenType"));
        return json.get("accessToken").asText();
    }

    private JsonNode authorize(String token, String resource, String action, Map<String, Object> extra) throws Exception {
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("accessToken", token);
        body.put("resource", resource);
        body.put("action", action);
        body.putAll(extra);
        log.info("输入: POST /gateway/authorize resource={} action={} extra={}", resource, action, extra);
        MvcResult result = mvc.perform(post("/gateway/authorize")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
        log.info("判定依据: allowed={} reason={} matched={} policyVersion={} roles={}",
                json.get("allowed"), json.get("reason"), json.get("matchedPolicyIds"),
                json.get("policyVersion"), json.get("roles"));
        return json;
    }

    @Test
    void roleInjectionAttemptIsIgnored() throws Exception {
        String token = login("alice", "alice-pass", Map.of("roles", List.of("writer", "admin")));

        JsonNode injected = authorize(token, "/docs", "write", Map.of("roles", List.of("writer")));
        assertFalse(injected.get("allowed").asBoolean(), "注入 writer 角色不得获得写权限");
        assertEquals("reader", injected.get("roles").get(0).asText(), "判定角色必须来自令牌");

        JsonNode normal = authorize(token, "/docs", "read", Map.of());
        assertTrue(normal.get("allowed").asBoolean());
    }

    @Test
    void tamperedAndMalformedTokensRejectedWithDistinctReasons() throws Exception {
        String token = login("bob", "bob-pass", Map.of());
        String[] parts = token.split("\\.", -1);
        char replacement = parts[1].charAt(0) == 'A' ? 'B' : 'A';
        String tampered = parts[0] + "." + replacement + parts[1].substring(1) + "." + parts[2];

        log.info("输入: 篡改载荷后的令牌");
        MvcResult r1 = mvc.perform(post("/gateway/authorize")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of(
                                "accessToken", tampered, "resource", "/docs", "action", "write"))))
                .andExpect(status().isUnauthorized())
                .andReturn();
        JsonNode e1 = mapper.readTree(r1.getResponse().getContentAsString());
        log.info("判定依据: error={} message={}", e1.get("error"), e1.get("message"));
        assertEquals("SIGNATURE_MISMATCH", e1.get("error").asText());

        log.info("输入: 非法格式令牌");
        MvcResult r2 = mvc.perform(post("/gateway/authorize")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of(
                                "accessToken", "garbage", "resource", "/docs", "action", "write"))))
                .andExpect(status().isUnauthorized())
                .andReturn();
        JsonNode e2 = mapper.readTree(r2.getResponse().getContentAsString());
        log.info("判定依据: error={} message={}", e2.get("error"), e2.get("message"));
        assertEquals("MALFORMED", e2.get("error").asText());
    }

    @Test
    void wrongCredentialsRejectedWithDistinctReason() throws Exception {
        log.info("输入: 错误密码登录");
        MvcResult result = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of(
                                "username", "alice", "password", "bad"))))
                .andExpect(status().isUnauthorized())
                .andReturn();
        JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
        log.info("判定依据: error={} message={}", json.get("error"), json.get("message"));
        assertEquals("INVALID_CREDENTIALS", json.get("error").asText());
    }

    @Test
    void policyHotUpdateAffectsSubsequentRequestsAndIsAudited() throws Exception {
        String token = login("alice", "alice-pass", Map.of());

        JsonNode before = authorize(token, "/docs", "read", Map.of());
        assertTrue(before.get("allowed").asBoolean());
        long v1 = before.get("policyVersion").asLong();

        JsonNode originalPolicies = mapper.readTree(mvc.perform(get("/admin/policies"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString())
                .get("policies");
        try {
            log.info("输入: POST /admin/policies 热更新为空策略集");
            mvc.perform(post("/admin/policies")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("[]"))
                    .andExpect(status().isOk());

            JsonNode after = authorize(token, "/docs", "read", Map.of());
            assertFalse(after.get("allowed").asBoolean(), "策略清空后同一令牌必须被拒绝");
            assertTrue(after.get("policyVersion").asLong() > v1, "判定必须使用新策略版本");
        } finally {
            mvc.perform(post("/admin/policies")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(mapper.writeValueAsString(originalPolicies)))
                    .andExpect(status().isOk());
        }

        MvcResult auditResult = mvc.perform(get("/admin/audit")).andExpect(status().isOk()).andReturn();
        JsonNode events = mapper.readTree(auditResult.getResponse().getContentAsString());
        List<JsonNode> docsReads = new ArrayList<>();
        events.forEach(e -> {
            if ("alice".equals(e.get("subject").asText())
                    && "/docs".equals(e.get("resource").asText())
                    && "read".equals(e.get("action").asText())) {
                docsReads.add(e);
            }
        });
        log.info("判定依据: 审计中 alice /docs read 事件数={}", docsReads.size());
        docsReads.forEach(e -> log.info("审计事件: allowed={} reason={} policyVersion={}",
                e.get("allowed"), e.get("reason"), e.get("policyVersion")));
        assertTrue(docsReads.size() >= 2, "允许与拒绝都必须留下审计记录");
        assertTrue(docsReads.stream().anyMatch(e -> e.get("allowed").asBoolean()));
        assertTrue(docsReads.stream().anyMatch(e -> !e.get("allowed").asBoolean()));
    }
}
