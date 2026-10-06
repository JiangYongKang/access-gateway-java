package com.github.highcumontoa.gateway.session;

/** 会话查询/下线操作失败的可区分原因。 */
public enum SessionFailureReason {
    UNKNOWN_SESSION,
    SESSION_NOT_OWNED_BY_SUBJECT
}
