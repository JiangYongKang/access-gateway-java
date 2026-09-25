package com.github.highcumontoa.accessgatewayjava.token;

/**
 * 令牌校验失败异常，携带可区分的拒绝原因。
 */
public class TokenException extends RuntimeException {

    private final TokenRejectReason reason;

    public TokenException(TokenRejectReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public TokenRejectReason getReason() {
        return reason;
    }
}
