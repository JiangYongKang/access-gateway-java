package com.github.highcumontoa.gateway.web;

import java.util.List;
import java.util.Map;
import com.github.highcumontoa.gateway.audit.AuditEventType;
import com.github.highcumontoa.gateway.audit.AuditLog;
import com.github.highcumontoa.gateway.session.SessionInfo;
import com.github.highcumontoa.gateway.session.SessionRegistry;
import com.github.highcumontoa.gateway.token.JwtService;
import com.github.highcumontoa.gateway.token.TokenValidationResult;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * 会话管理端点（用户视角，Bearer 访问令牌鉴权）：
 * 查看自己的活跃会话、下线单个会话、下线全部会话。
 * 响应只包含建立时间/最近活动时间/状态，不暴露任何凭据。
 * 被下线的会话，其访问令牌立即以 SESSION_REVOKED 拒绝（与令牌自身非法/过期可区分）。
 */
@RestController
@RequestMapping("/auth/sessions")
public class SessionController {
    private final JwtService jwtService;
    private final SessionRegistry sessionRegistry;
    private final AuditLog auditLog;

    public SessionController(JwtService jwtService, SessionRegistry sessionRegistry, AuditLog auditLog) {
        this.jwtService = jwtService;
        this.sessionRegistry = sessionRegistry;
        this.auditLog = auditLog;
    }

    /** 当前用户的活跃会话列表（建立时间、最近活动时间、状态）。 */
    @GetMapping
    public ResponseEntity<?> listSessions(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        ResponseEntity<?> error = requireValidToken(authorization);
        if (error != null) {
            return error;
        }
        String subject = jwtService.validate(authorization.substring(7)).claims().subject();
        List<SessionInfo> sessions = sessionRegistry.sessionsFor(subject);
        return ResponseEntity.ok(Map.of("sessions", sessions));
    }

    /** 下线指定会话（仅限本人的会话；他人或不存在的会话一律 404）。 */
    @DeleteMapping("/{sessionId}")
    public ResponseEntity<?> terminateOne(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @PathVariable String sessionId) {
        ResponseEntity<?> error = requireValidToken(authorization);
        if (error != null) {
            return error;
        }
        String subject = jwtService.validate(authorization.substring(7)).claims().subject();
        SessionInfo session = sessionRegistry.find(sessionId).orElse(null);
        if (session == null || !session.username().equals(subject)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "SESSION_NOT_FOUND"));
        }
        sessionRegistry.revoke(sessionId);
        auditLog.record(AuditEventType.SESSION_TERMINATED, subject, sessionId, null,
                "session", "terminate", true, "用户主动下线单个会话");
        return ResponseEntity.noContent().build();
    }

    /** 下线当前用户的全部会话（含发起请求的会话本身）。 */
    @DeleteMapping
    public ResponseEntity<?> terminateAll(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        ResponseEntity<?> error = requireValidToken(authorization);
        if (error != null) {
            return error;
        }
        String subject = jwtService.validate(authorization.substring(7)).claims().subject();
        List<SessionInfo> active = sessionRegistry.sessionsFor(subject);
        int terminated = sessionRegistry.revokeAllForUser(subject);
        for (SessionInfo session : active) {
            auditLog.record(AuditEventType.SESSION_TERMINATED, subject, session.sessionId(), null,
                    "session", "terminate-all", true, "用户主动下线全部会话");
        }
        return ResponseEntity.ok(Map.of("terminated", terminated));
    }

    /** 校验 Bearer 令牌；合法返回 null，否则返回应直接响应的错误实体。 */
    private ResponseEntity<?> requireValidToken(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "MISSING_BEARER_TOKEN"));
        }
        TokenValidationResult validation = jwtService.validate(authorization.substring(7));
        if (!validation.isValid()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", validation.failureReason().name()));
        }
        return null;
    }
}
