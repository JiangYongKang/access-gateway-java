package com.github.highcumontoa.accessgatewayjava.web;

import com.github.highcumontoa.accessgatewayjava.auth.AuthException;
import com.github.highcumontoa.accessgatewayjava.token.TokenException;
import com.github.highcumontoa.accessgatewayjava.web.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;

/**
 * 统一异常映射：将可区分的原因码转换为 HTTP 响应。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /** 令牌校验失败：401 + 令牌拒绝原因码。 */
    @ExceptionHandler(TokenException.class)
    public ResponseEntity<ErrorResponse> tokenError(TokenException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse(e.getReason().name(), e.getMessage(), Instant.now()));
    }

    /** 认证/会话失败：401 + 认证原因码。 */
    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorResponse> authError(AuthException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse(e.getError().name(), e.getMessage(), Instant.now()));
    }

    /** 请求参数问题：400。 */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> badRequest(IllegalArgumentException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse("BAD_REQUEST", e.getMessage(), Instant.now()));
    }
}
