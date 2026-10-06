package com.github.highcumontoa.gateway.audit;

import java.time.Instant;

/** 审计查询条件：null 字段表示不按该维度筛选；时间范围含端点。 */
public record AuditQuery(
        String subject,
        String sessionId,
        String action,
        String outcome,
        Instant from,
        Instant to) {

    public static AuditQuery all() {
        return new AuditQuery(null, null, null, null, null, null);
    }
}
