package com.github.highcumontoa.accessgatewayjava.tests;

import com.github.highcumontoa.accessgatewayjava.policy.Decision;
import com.github.highcumontoa.accessgatewayjava.policy.Policy;
import com.github.highcumontoa.accessgatewayjava.tests.support.TestGateway;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 策略判定：默认拒绝、DENY 优先、热更新立即生效、判定依据可追溯。
 */
class PolicyEngineTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyEngineTest.class);

    private Decision decideAndLog(TestGateway gw, Set<String> roles, String resource, String action) {
        log.info("输入: roles={} resource={} action={}", roles, resource, action);
        Decision d = gw.engine.decide(roles, resource, action);
        log.info("判定依据: allowed={} reason={} matched={} policyVersion={}",
                d.allowed(), d.reason(), d.matchedPolicyIds(), d.policyVersion());
        return d;
    }

    @Test
    void defaultDenyWhenNoPolicyMatches() {
        TestGateway gw = TestGateway.create();
        Decision d = decideAndLog(gw, Set.of("reader"), "/secret", "read");
        assertFalse(d.allowed());
        assertTrue(d.matchedPolicyIds().isEmpty());
        assertTrue(d.reason().contains("默认拒绝"));
    }

    @Test
    void emptyRolesDenied() {
        TestGateway gw = TestGateway.create();
        Decision d = decideAndLog(gw, Set.of(), "/docs", "read");
        assertFalse(d.allowed());
        assertTrue(d.reason().contains("默认拒绝"));
    }

    @Test
    void allowWhenPolicyMatches() {
        TestGateway gw = TestGateway.create();
        Decision d = decideAndLog(gw, Set.of("reader"), "/docs", "read");
        assertTrue(d.allowed());
        assertEquals(List.of("p-allow-reader-read-docs"), d.matchedPolicyIds());
    }

    @Test
    void denyTakesPrecedenceOverAllow() {
        TestGateway gw = TestGateway.create();
        long v = gw.policyStore.replaceAll(List.of(
                new Policy("p-allow-writer-delete", "writer", "/docs", "delete", Policy.Effect.ALLOW),
                new Policy("p-deny-writer-delete", "writer", "/docs", "delete", Policy.Effect.DENY)));
        log.info("输入: 同时配置 ALLOW 与 DENY 策略，policyVersion={}", v);

        Decision d = decideAndLog(gw, Set.of("writer"), "/docs", "delete");
        assertFalse(d.allowed());
        assertEquals(List.of("p-deny-writer-delete"), d.matchedPolicyIds());
        assertTrue(d.reason().contains("拒绝优先"));
    }

    @Test
    void policyChangeTakesEffectImmediatelyAndConsistently() {
        TestGateway gw = TestGateway.create();
        Set<String> roles = Set.of("reader");

        Decision before = decideAndLog(gw, roles, "/docs", "read");
        assertTrue(before.allowed());
        long v1 = before.policyVersion();

        long v2 = gw.policyStore.replaceAll(List.of());
        log.info("输入: 热更新为空策略集，version {} -> {}", v1, v2);
        Decision after1 = decideAndLog(gw, roles, "/docs", "read");
        Decision after2 = decideAndLog(gw, roles, "/docs", "read");
        assertFalse(after1.allowed());
        assertEquals(after1.allowed(), after2.allowed());
        assertEquals(after1.reason(), after2.reason());
        assertEquals(v2, after1.policyVersion());

        long v3 = gw.policyStore.replaceAll(List.of(
                new Policy("p-reader-docs-read-v3", "reader", "/docs", "read", Policy.Effect.ALLOW)));
        log.info("输入: 再次热更新恢复允许策略，version {} -> {}", v2, v3);
        Decision restored = decideAndLog(gw, roles, "/docs", "read");
        assertTrue(restored.allowed());
        assertEquals(List.of("p-reader-docs-read-v3"), restored.matchedPolicyIds());
        assertEquals(v3, restored.policyVersion());
    }
}
