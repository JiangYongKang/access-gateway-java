package com.github.highcumontoa.accessgatewayjava.web;

import com.github.highcumontoa.accessgatewayjava.audit.AuditEvent;
import com.github.highcumontoa.accessgatewayjava.audit.AuditService;
import com.github.highcumontoa.accessgatewayjava.policy.Policy;
import com.github.highcumontoa.accessgatewayjava.policy.PolicyStore;
import com.github.highcumontoa.accessgatewayjava.token.KeyInfo;
import com.github.highcumontoa.accessgatewayjava.token.KeyService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 管理端点：策略热更新、密钥轮换、审计查询（本地演示用途，未加保护）。
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    private final PolicyStore policyStore;
    private final KeyService keyService;
    private final AuditService auditService;

    public AdminController(PolicyStore policyStore, KeyService keyService, AuditService auditService) {
        this.policyStore = policyStore;
        this.keyService = keyService;
        this.auditService = auditService;
    }

    @GetMapping("/policies")
    public Map<String, Object> listPolicies() {
        return Map.of("version", policyStore.version(), "policies", policyStore.snapshot());
    }

    @PostMapping("/policies")
    public Map<String, Object> replacePolicies(@RequestBody List<Policy> policies) {
        long newVersion = policyStore.replaceAll(policies);
        return Map.of("version", newVersion);
    }

    @PostMapping("/keys/rotate")
    public KeyInfo rotateKey() {
        return keyService.rotate();
    }

    @GetMapping("/keys")
    public List<KeyInfo> listKeys() {
        return keyService.listKeys();
    }

    @GetMapping("/audit")
    public List<AuditEvent> audit() {
        return auditService.list();
    }
}
