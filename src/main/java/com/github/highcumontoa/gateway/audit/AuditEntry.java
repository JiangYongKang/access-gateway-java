package com.github.highcumontoa.gateway.audit;

import java.time.Instant;
import java.util.List;

/** 审计条目：每次允许/拒绝的可追溯判定依据。 */
public record AuditEntry(
        Instant at,
        String subject,
        List<String> roles,
        String resource,
        String action,
        boolean allowed,
        String reason) {}
