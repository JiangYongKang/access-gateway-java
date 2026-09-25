package com.github.highcumontoa.accessgatewayjava.web;

import com.github.highcumontoa.accessgatewayjava.auth.AuthService;
import com.github.highcumontoa.accessgatewayjava.auth.IssuedTokens;
import com.github.highcumontoa.accessgatewayjava.web.dto.LoginRequest;
import com.github.highcumontoa.accessgatewayjava.web.dto.RefreshRequest;
import com.github.highcumontoa.accessgatewayjava.web.dto.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 认证端点：登录、刷新、吊销。
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request) {
        if (request.roles() != null && !request.roles().isEmpty()) {
            log.warn("忽略登录请求中客户端自报角色 {}", request.roles());
        }
        return toResponse(authService.login(request.username(), request.password(), request.audience()));
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request) {
        if (request.roles() != null && !request.roles().isEmpty()) {
            log.warn("忽略刷新请求中客户端自报角色 {}", request.roles());
        }
        return toResponse(authService.refresh(request.refreshToken()));
    }

    @PostMapping("/revoke")
    public Map<String, Object> revoke(@RequestBody Map<String, String> body) {
        boolean revoked = authService.revoke(body.get("familyId"));
        return Map.of("revoked", revoked);
    }

    private TokenResponse toResponse(IssuedTokens tokens) {
        return new TokenResponse(tokens.accessToken(), tokens.accessExpiresAt(),
                tokens.refreshToken(), tokens.refreshExpiresAt(), tokens.familyId(), "Bearer");
    }
}
