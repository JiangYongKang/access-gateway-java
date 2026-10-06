package com.github.highcumontoa.gateway.web;

import java.util.List;
import java.util.Map;
import com.github.highcumontoa.gateway.audit.AuditEventType;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.policy.AccessDecision;
import com.github.highcumontoa.gateway.policy.PolicyEngine;
import com.github.highcumontoa.gateway.token.AccessTokenClaims;
import com.github.highcumontoa.gateway.token.JwtService;
import com.github.highcumontoa.gateway.token.TokenValidationResult;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * 受保护资源端点。判定顺序：
 *  1. 令牌校验（失败原因可区分，直接 401）；
 *  2. 策略判定（默认拒绝，结果可解释）；
 *  3. 审计留痕（允许与拒绝都记录判定依据）。
 */
@RestController
@RequestMapping("/api")
public class ResourceController {
    private final JwtService jwtService;
    private final PolicyEngine policyEngine;
    private final AuditLog auditLog;

    public ResourceController(JwtService jwtService, PolicyEngine policyEngine, AuditLog auditLog) {
        this.jwtService = jwtService;
        this.policyEngine = policyEngine;
        this.auditLog = auditLog;
    }

    @GetMapping("/documents")
    public ResponseEntity<?> readDocuments(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        return guard(authorization, "documents", "read");
    }

    @PostMapping("/documents")
    public ResponseEntity<?> writeDocuments(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        return guard(authorization, "documents", "write");
    }

    private ResponseEntity<?> guard(String authorization, String resource, String action) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "MISSING_BEARER_TOKEN"));
        }
        TokenValidationResult validation = jwtService.validate(authorization.substring(7));
        if (!validation.isValid()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", validation.failureReason().name()));
        }
        AccessTokenClaims claims = validation.claims();
        AccessDecision decision = policyEngine.evaluate(claims.roles(), resource, action);
        auditLog.record(AuditEventType.ACCESS, claims.subject(), claims.sessionFamily(), claims.roles(),
                resource, action, decision.allowed(), decision.reason());
        if (!decision.allowed()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "ACCESS_DENIED", "reason", decision.reason()));
        }
        return ResponseEntity.ok(Map.of(
                "subject", claims.subject(),
                "resource", resource,
                "action", action,
                "matchedPolicies", decision.matchedPolicies()));
    }
}
