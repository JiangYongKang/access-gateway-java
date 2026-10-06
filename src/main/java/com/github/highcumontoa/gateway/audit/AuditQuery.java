package com.github.highcumontoa.gateway.audit;

import java.time.Instant;

/**
 * 审计查询条件：全部字段可空，空表示不限制。
 * from/to 为闭区间边界（at >= from 且 at <= to）。
 */
public record AuditQuery(
        String subject,
        String sessionId,
        Boolean allowed,
        String eventType,
        Instant from,
        Instant to) {

    public static AuditQuery all() {
        return new AuditQuery(null, null, null, null, null, null);
    }
}
