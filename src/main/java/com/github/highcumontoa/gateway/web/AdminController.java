package com.github.highcumontoa.gateway.web;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.audit.AuditQuery;
import com.github.highcumontoa.gateway.policy.Policy;
import com.github.highcumontoa.gateway.policy.PolicyEngine;
import com.github.highcumontoa.gateway.token.KeyManager;
import com.github.highcumontoa.gateway.token.SigningKey;
import org.springframework.web.bind.annotation.*;

/** 管理端点：策略热更新、密钥轮换、审计查询（本地演示用，未加保护）。 */
@RestController
@RequestMapping("/admin")
public class AdminController {
    private final PolicyEngine policyEngine;
    private final KeyManager keyManager;
    private final AuditLog auditLog;

    public AdminController(PolicyEngine policyEngine, KeyManager keyManager, AuditLog auditLog) {
        this.policyEngine = policyEngine;
        this.keyManager = keyManager;
        this.auditLog = auditLog;
    }

    @GetMapping("/policies")
    public List<Policy> policies() {
        return policyEngine.currentPolicies();
    }

    /** 热更新策略：立即对后续请求生效，无需重启。 */
    @PutMapping("/policies")
    public List<Policy> replacePolicies(@RequestBody List<Policy> policies) {
        policyEngine.replacePolicies(policies);
        return policyEngine.currentPolicies();
    }

    /** 轮换签名密钥：旧密钥进入重叠期。 */
    @PostMapping("/keys/rotate")
    public Map<String, Object> rotateKey() {
        SigningKey fresh = keyManager.rotate();
        return Map.of("currentKeyId", fresh.keyId(), "keys", keyManager.allKeys().stream()
                .map(k -> Map.of("keyId", k.keyId(),
                        "retiredAt", k.retiredAt() == null ? "null" : k.retiredAt().toString()))
                .toList());
    }

    /** 审计查询：支持按主体、会话、结论、事件类型与时间范围筛选（参数均可空）。 */
    @GetMapping("/audit")
    public Object audit(
            @RequestParam(required = false) String subject,
            @RequestParam(required = false) String sessionId,
            @RequestParam(required = false) Boolean allowed,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to) {
        return auditLog.query(new AuditQuery(subject, sessionId, allowed, eventType,
                from == null ? null : Instant.parse(from),
                to == null ? null : Instant.parse(to)));
    }
}
