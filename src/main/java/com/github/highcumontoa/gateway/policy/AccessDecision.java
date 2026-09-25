package com.github.highcumontoa.gateway.policy;

import java.util.List;

/** 判定结果与可解释依据。 */
public record AccessDecision(boolean allowed, String reason, List<String> matchedPolicies) {
    public static AccessDecision allow(String reason, List<String> matched) {
        return new AccessDecision(true, reason, matched);
    }
    public static AccessDecision deny(String reason) {
        return new AccessDecision(false, reason, List.of());
    }
}
