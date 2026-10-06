package com.github.highcumontoa.gateway.web;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import com.github.highcumontoa.gateway.audit.AuditAction;
import com.github.highcumontoa.gateway.audit.AuditEntry;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.audit.AuditOutcome;
import com.github.highcumontoa.gateway.policy.AccessDecision;
import com.github.highcumontoa.gateway.policy.PolicyEngine;
import com.github.highcumontoa.gateway.session.SessionService;
import com.github.highcumontoa.gateway.token.AccessTokenClaims;
import com.github.highcumontoa.gateway.token.JwtService;
import com.github.highcumontoa.gateway.token.TokenFailureReason;
import com.github.highcumontoa.gateway.token.TokenValidationResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * 受保护资源端点。判定顺序：
 *  1. Bearer 存在性（缺失 → 401 MISSING_BEARER_TOKEN）；
 *  2. 令牌校验（签名/密钥/iss/aud/时效等，失败原因可区分 → 401）；
 *  3. 会话守卫（令牌合法但所属会话已被下线/吊销 → 401 SESSION_REVOKED）；
 *  4. 策略判定（默认拒绝，结果可解释）；
 *  5. 审计留痕（允许与拒绝都记录判定依据）。
 */
@RestController
@RequestMapping("/api")
public class ResourceController {
    private final JwtService jwtService;
    private final PolicyEngine policyEngine;
    private final AuditLog auditLog;
    private final SessionService sessionService;

    @Autowired
    public ResourceController(JwtService jwtService, PolicyEngine policyEngine,
                              AuditLog auditLog, SessionService sessionService) {
        this.jwtService = jwtService;
        this.policyEngine = policyEngine;
        this.auditLog = auditLog;
        this.sessionService = sessionService;
    }

    /** 兼容构造：不接入会话层时不做会话守卫（旧单元测试使用）。 */
    public ResourceController(JwtService jwtService, PolicyEngine policyEngine, AuditLog auditLog) {
        this(jwtService, policyEngine, auditLog, null);
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

        if (sessionService != null && !sessionService.isSessionActive(claims.sessionFamily())) {
            String reason = "令牌合法但所属会话已被下线/吊销 family=" + claims.sessionFamily();
            auditLog.record(new AuditEntry(-1L, Instant.now(), AuditAction.RESOURCE_ACCESS,
                    claims.subject(), claims.sessionFamily(), AuditOutcome.REVOKED, false,
                    claims.roles(), resource, action, reason));
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", TokenFailureReason.SESSION_REVOKED.name(), "reason", reason));
        }

        AccessDecision decision = policyEngine.evaluate(claims.roles(), resource, action);
        auditLog.record(new AuditEntry(Instant.now(), claims.subject(), claims.roles(),
                resource, action, decision.allowed(), decision.reason()));
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
