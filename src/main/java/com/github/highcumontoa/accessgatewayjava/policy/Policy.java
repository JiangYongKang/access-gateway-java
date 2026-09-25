package com.github.highcumontoa.accessgatewayjava.policy;

import java.util.Set;

/**
 * 一条访问策略：某角色对某资源执行某动作的允许/拒绝规则。
 */
public record Policy(String id, String role, String resource, String action, Effect effect) {

    public enum Effect {
        ALLOW, DENY
    }

    public boolean matches(String candidateRole, String candidateResource, String candidateAction) {
        return role.equals(candidateRole) && resource.equals(candidateResource) && action.equals(candidateAction);
    }
}
