package com.github.highcumontoa.gateway.token;

/** 刷新令牌失败的可区分原因。 */
public enum RefreshFailureReason {
    UNKNOWN_TOKEN,
    EXPIRED,
    ALREADY_USED_REUSE_DETECTED,
    FAMILY_REVOKED
}
