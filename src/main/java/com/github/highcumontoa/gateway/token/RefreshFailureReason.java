package com.github.highcumontoa.gateway.token;

/** 刷新令牌失败的可区分原因。 */
public enum RefreshFailureReason {
    UNKNOWN_TOKEN,
    EXPIRED,
    ALREADY_USED_REUSE_DETECTED,
    FAMILY_REVOKED,
    /** 闲置超时：距该会话族上一次刷新活动超过配置的闲置时长。 */
    IDLE_TIMEOUT,
    /** 到达总续期上限：会话自建立起的总寿命已到，连续轮换也不能续命。 */
    TOTAL_LIFETIME_REACHED
}
