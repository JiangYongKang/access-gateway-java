package com.github.highcumontoa.accessgatewayjava.web.dto;

import java.util.List;
import java.util.Set;

/**
 * 访问判定响应：结论 + 判定依据。
 */
public record AuthorizeResponse(boolean allowed, String reason, List<String> matchedPolicyIds,
                                long policyVersion, String subject, Set<String> roles) {
}
