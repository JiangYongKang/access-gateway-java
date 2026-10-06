package com.github.highcumontoa.gateway.token;

/** 刷新令牌失败的可区分原因。 */
public enum RefreshFailureReason {
    UNKNOWN_TOKEN,
    EXPIRED,
    ALREADY_USED_REUSE_DETECTED,
    FAMILY_REVOKED,
    /** 会话超过闲置超时（长期无刷新活动）而失效。 */
    SESSION_IDLE_TIMEOUT,
    /** 会话到达自建立起的总最长可续期时间。 */
    SESSION_MAX_LIFETIME_EXCEEDED
}
