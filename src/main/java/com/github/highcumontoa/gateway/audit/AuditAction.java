package com.github.highcumontoa.gateway.audit;

/** 审计动作类型。 */
public final class AuditAction {
    /** 会话建立（凭证换令牌成功）。 */
    public static final String SESSION_CREATED = "SESSION_CREATED";
    /** 刷新令牌轮换。 */
    public static final String REFRESH = "REFRESH";
    /** 主动下线单个会话。 */
    public static final String SESSION_TERMINATED = "SESSION_TERMINATED";
    /** 一次性下线某主体的全部会话。 */
    public static final String SESSIONS_TERMINATED_ALL = "SESSIONS_TERMINATED_ALL";
    /** 受保护资源访问判定。 */
    public static final String RESOURCE_ACCESS = "RESOURCE_ACCESS";

    private AuditAction() {}
}
