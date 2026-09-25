package com.github.highcumontoa.gateway.web;

import java.util.Map;
import com.github.highcumontoa.gateway.auth.CredentialStore;
import com.github.highcumontoa.gateway.token.RefreshResult;
import com.github.highcumontoa.gateway.token.RefreshTokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** 认证端点：凭证校验换令牌、刷新、吊销。 */
@RestController
@RequestMapping("/auth")
public class AuthController {
    private final CredentialStore credentialStore;
    private final RefreshTokenService refreshTokenService;

    public AuthController(CredentialStore credentialStore, RefreshTokenService refreshTokenService) {
        this.credentialStore = credentialStore;
        this.refreshTokenService = refreshTokenService;
    }

    public record TokenRequest(String username, String password) {}
    public record RefreshRequest(String refreshToken) {}

    @PostMapping("/token")
    public ResponseEntity<?> token(@RequestBody TokenRequest request) {
        return credentialStore.verify(request.username(), request.password())
                .<ResponseEntity<?>>map(account -> {
                    String[] pair = refreshTokenService.issueInitialTokenPair(account.username());
                    return ResponseEntity.ok(Map.of(
                            "accessToken", pair[0], "refreshToken", pair[1], "tokenType", "Bearer"));
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "INVALID_CREDENTIALS")));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {
        RefreshResult result = refreshTokenService.rotate(request.refreshToken());
        if (result.isSuccess()) {
            return ResponseEntity.ok(Map.of(
                    "accessToken", result.accessToken(),
                    "refreshToken", result.refreshToken(),
                    "tokenType", "Bearer"));
        }
        // 重用检测与族吊销属于安全事件，返回 403；其余为 401。
        HttpStatus status = switch (result.failureReason()) {
            case ALREADY_USED_REUSE_DETECTED, FAMILY_REVOKED -> HttpStatus.FORBIDDEN;
            default -> HttpStatus.UNAUTHORIZED;
        };
        return ResponseEntity.status(status).body(Map.of("error", result.failureReason().name()));
    }

    @PostMapping("/revoke")
    public ResponseEntity<?> revoke(@RequestBody RefreshRequest request) {
        refreshTokenService.revokeFamily(request.refreshToken());
        return ResponseEntity.noContent().build();
    }
}
