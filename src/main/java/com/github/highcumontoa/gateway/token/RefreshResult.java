package com.github.highcumontoa.gateway.token;

/** 刷新结果：成功返回新访问令牌与新刷新令牌；失败给出可区分原因。 */
public record RefreshResult(String accessToken, String refreshToken, RefreshFailureReason failureReason) {
    public static RefreshResult ok(String accessToken, String refreshToken) {
        return new RefreshResult(accessToken, refreshToken, null);
    }
    public static RefreshResult fail(RefreshFailureReason reason) {
        return new RefreshResult(null, null, reason);
    }
    public boolean isSuccess() { return failureReason == null; }
}
