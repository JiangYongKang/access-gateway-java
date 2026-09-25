package com.github.highcumontoa.gateway.policy;

import java.util.List;

/** 访问策略：某角色对某资源与动作是否允许。默认拒绝。 */
public record Policy(String role, String resource, String action, boolean allow) {
    public boolean matches(List<String> roles, String res, String act) {
        return role.equals("*") || roles.contains(role);
    }
}
