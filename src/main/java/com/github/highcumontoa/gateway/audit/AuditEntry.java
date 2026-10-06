package com.github.highcumontoa.gateway.audit;

import java.time.Instant;
import java.util.List;

/**
 * 审计条目：安全相关动作的可追溯记录。
 * 除资源访问外，会话建立、刷新轮换、主动下线/踢人、刷新令牌重用检测也写入审计。
 * 字段刻意不带任何凭据内容（无口令、无令牌原文）。
 */
public record AuditEntry(
        long sequence,
        Instant at,
        String action,
        String subject,
        String sessionId,
        String outcome,
        boolean success,
        List<String> roles,
        String resource,
        String act,
        String detail) {

    /** 兼容资源访问审计的旧构造方式（序列由审计日志分配，故此处为 -1 占位）。 */
    public AuditEntry(Instant at, String subject, List<String> roles,
                      String resource, String action, boolean allowed, String reason) {
        this(-1L, at, AuditAction.RESOURCE_ACCESS, subject, null,
                allowed ? AuditOutcome.ALLOWED : AuditOutcome.DENIED, allowed,
                roles, resource, action, reason);
    }

    /** 兼容旧代码：判定依据即明细字段。 */
    public String reason() {
        return detail;
    }

    /** 兼容旧代码：是否放行（资源访问场景）。 */
    public boolean allowed() {
        return success;
    }
}
