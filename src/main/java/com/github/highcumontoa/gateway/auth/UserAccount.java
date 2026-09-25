package com.github.highcumontoa.gateway.auth;

import java.util.List;

/** 进程内用户档案：口令只存加盐哈希，角色由服务端维护。 */
public record UserAccount(String username, String passwordHash, String salt, List<String> roles, boolean enabled) {}
