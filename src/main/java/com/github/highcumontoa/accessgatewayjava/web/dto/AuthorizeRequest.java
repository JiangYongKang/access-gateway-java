package com.github.highcumontoa.accessgatewayjava.web.dto;

import java.util.Set;

/**
 * 访问判定请求。
 * audience 缺省时使用网关默认受众；roles 字段为伪造注入入口：判定只使用令牌内角色。
 */
public record AuthorizeRequest(String accessToken, String resource, String action,
                               String audience, Set<String> roles) {
}
