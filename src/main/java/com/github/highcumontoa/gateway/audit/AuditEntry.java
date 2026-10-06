package com.github.highcumontoa.gateway.audit;

import java.time.Instant;
import java.util.List;

/**
 * 审计条目：每次放行/拒绝的可追溯判定依据。
 * sequence 由 AuditLog 单调分配，保证淘汰后剩余记录顺序稳定。
 */
public record AuditEntry(
        long sequence,
        Instant at,
        String eventType,
        String subject,
        String sessionId,
        List<String> roles,
        String resource,
        String action,
        boolean allowed,
        String reason) {}
