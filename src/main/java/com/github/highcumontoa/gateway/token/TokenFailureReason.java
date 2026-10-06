package com.github.highcumontoa.gateway.token;

/** 访问令牌校验失败的可区分原因。 */
public enum TokenFailureReason {
    MALFORMED,
    BAD_SIGNATURE,
    UNKNOWN_KEY,
    KEY_RETIRED,
    ISSUER_MISMATCH,
    AUDIENCE_MISMATCH,
    EXPIRED,
    NOT_YET_VALID,
    /** 令牌本身合法且未过期，但所属会话已被主动下线/吊销。 */
    SESSION_REVOKED
}
