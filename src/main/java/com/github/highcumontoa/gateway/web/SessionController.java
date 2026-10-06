package com.github.highcumontoa.gateway.web;

import java.util.List;
import java.util.Map;
import com.github.highcumontoa.gateway.session.SessionFailureReason;
import com.github.highcumontoa.gateway.session.SessionInfo;
import com.github.highcumontoa.gateway.session.SessionService;
import com.github.highcumontoa.gateway.token.JwtService;
import com.github.highcumontoa.gateway.token.TokenValidationResult;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * 会话自助管理端点（由调用者自己的访问令牌识别主体）：
 *  - GET  /auth/sessions           查看自己的会话（建立时间、最近活动、状态；不含任何凭据）
 *  - POST /auth/sessions/{id}/terminate 下线其中一个会话
 *  - POST /auth/sessions/terminate-all   一次性下线自己的全部会话
 */
@RestController
@RequestMapping("/auth/sessions")
public class SessionController {
    private final JwtService jwtService;
    private final SessionService sessionService;

    public SessionController(JwtService jwtService, SessionService sessionService) {
        this.jwtService = jwtService;
        this.sessionService = sessionService;
    }

    @GetMapping
    public ResponseEntity<?> list(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        ResponseEntity<?> unauthenticated = authenticate(authorization);
        if (unauthenticated != null) {
            return unauthenticated;
        }
        String subject = jwtService.validate(authorization.substring(7)).claims().subject();
        List<SessionInfo> sessions = sessionService.listSessions(subject);
        return ResponseEntity.ok(Map.of("subject", subject, "sessions", sessions));
    }

    @PostMapping("/{sessionId}/terminate")
    public ResponseEntity<?> terminate(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @PathVariable String sessionId) {
        ResponseEntity<?> unauthenticated = authenticate(authorization);
        if (unauthenticated != null) {
            return unauthenticated;
        }
        String subject = jwtService.validate(authorization.substring(7)).claims().subject();
        SessionFailureReason reason = sessionService.terminate(subject, sessionId);
        if (reason == null) {
            return ResponseEntity.noContent().build();
        }
        HttpStatus status = reason == SessionFailureReason.SESSION_NOT_OWNED_BY_SUBJECT
                ? HttpStatus.FORBIDDEN : HttpStatus.NOT_FOUND;
        return ResponseEntity.status(status).body(Map.of("error", reason.name()));
    }

    @PostMapping("/terminate-all")
    public ResponseEntity<?> terminateAll(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        ResponseEntity<?> unauthenticated = authenticate(authorization);
        if (unauthenticated != null) {
            return unauthenticated;
        }
        String subject = jwtService.validate(authorization.substring(7)).claims().subject();
        int terminated = sessionService.terminateAll(subject);
        return ResponseEntity.ok(Map.of("terminated", terminated));
    }

    /**
     * 用访问令牌识别主体。令牌本身非法（含已被下线的会话）一律 401，
     * 其中会话被下线使用可区分的 SESSION_REVOKED。
     * 返回 null 表示认证通过。
     */
    private ResponseEntity<?> authenticate(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "MISSING_BEARER_TOKEN"));
        }
        TokenValidationResult validation = jwtService.validate(authorization.substring(7));
        if (!validation.isValid()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", validation.failureReason().name()));
        }
        if (!sessionService.isSessionActive(validation.claims().sessionFamily())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "SESSION_REVOKED"));
        }
        return null;
    }
}
