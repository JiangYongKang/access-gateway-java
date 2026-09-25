package com.github.highcumontoa.accessgatewayjava.web.dto;

import java.util.Set;

/**
 * 登录请求。roles 字段为伪造注入入口：服务端一律忽略，仅以身份库角色为准。
 */
public record LoginRequest(String username, String password, String audience, Set<String> roles) {
}
