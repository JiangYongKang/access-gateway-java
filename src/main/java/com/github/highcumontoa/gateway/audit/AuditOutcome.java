package com.github.highcumontoa.gateway.audit;

/** 审计结论（结果类别），用于按结论筛选。 */
public final class AuditOutcome {
    public static final String SUCCESS = "SUCCESS";
    public static final String DENIED = "DENIED";
    public static final String REVOKED = "REVOKED";
    public static final String REUSE_DETECTED = "REUSE_DETECTED";
    public static final String EXPIRED = "EXPIRED";
    public static final String IDLE_TIMEOUT = "IDLE_TIMEOUT";
    public static final String MAX_LIFETIME = "MAX_LIFETIME";
    public static final String UNKNOWN_TOKEN = "UNKNOWN_TOKEN";
    /** 资源访问策略放行。 */
    public static final String ALLOWED = "ALLOWED";

    private AuditOutcome() {}
}
