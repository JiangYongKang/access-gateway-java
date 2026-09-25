package com.github.highcumontoa.gateway.token;

/** 令牌校验结果：要么成功携带声明，要么失败携带可区分原因。 */
public record TokenValidationResult(AccessTokenClaims claims, TokenFailureReason failureReason) {
    public static TokenValidationResult ok(AccessTokenClaims claims) {
        return new TokenValidationResult(claims, null);
    }
    public static TokenValidationResult fail(TokenFailureReason reason) {
        return new TokenValidationResult(null, reason);
    }
    public boolean isValid() { return failureReason == null; }
}
