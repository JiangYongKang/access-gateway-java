package com.github.highcumontoa.gateway.audit;

/** 审计事件类型常量。 */
public final class AuditEventType {
    /** 受保护资源的访问判定（允许/拒绝）。 */
    public static final String ACCESS = "ACCESS";
    /** 会话建立（凭证换令牌）。 */
    public static final String SESSION_ESTABLISHED = "SESSION_ESTABLISHED";
    /** 刷新轮换成功。 */
    public static final String SESSION_REFRESHED = "SESSION_REFRESHED";
    /** 会话被主动下线/踢人（含重用检测触发的吊销之外的显式下线）。 */
    public static final String SESSION_TERMINATED = "SESSION_TERMINATED";
    /** 刷新令牌重用检测。 */
    public static final String REFRESH_REUSE_DETECTED = "REFRESH_REUSE_DETECTED";

    private AuditEventType() {}
}
