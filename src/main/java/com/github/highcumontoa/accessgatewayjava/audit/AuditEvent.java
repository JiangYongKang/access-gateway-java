package com.github.highcumontoa.accessgatewayjava.audit;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * 一条可追溯的判定审计记录。
 */
public record AuditEvent(Instant at, String subject, Set<String> roles,
                         String resource, String action, boolean allowed,
                         String reason, List<String> matchedPolicyIds, long policyVersion) {
}
