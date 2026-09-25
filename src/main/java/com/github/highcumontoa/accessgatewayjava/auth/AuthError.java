package com.github.highcumontoa.accessgatewayjava.auth;

/**
 * 认证/会话失败的可区分原因码。
 */
public enum AuthError {
    /** 凭证校验失败（用户名或密码错误）。 */
    INVALID_CREDENTIALS,
    /** 刷新令牌校验失败（过期、被篡改、类型或受众不符等）。 */
    INVALID_REFRESH_TOKEN,
    /** 刷新令牌已被轮换或吊销。 */
    REFRESH_TOKEN_REVOKED,
    /** 检测到刷新令牌重用，所属会话族已被整体吊销且不可恢复。 */
    REFRESH_TOKEN_REUSED,
    /** 会话族不存在。 */
    FAMILY_NOT_FOUND
}
