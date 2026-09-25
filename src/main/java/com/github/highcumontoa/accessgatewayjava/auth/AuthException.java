package com.github.highcumontoa.accessgatewayjava.auth;

/**
 * 认证/会话失败异常，携带可区分的原因码。
 */
public class AuthException extends RuntimeException {

    private final AuthError error;

    public AuthException(AuthError error, String message) {
        super(message);
        this.error = error;
    }

    public AuthError getError() {
        return error;
    }
}
