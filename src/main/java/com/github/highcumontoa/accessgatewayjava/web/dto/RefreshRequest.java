package com.github.highcumontoa.accessgatewayjava.web.dto;

import java.util.Set;

/**
 * 刷新请求。roles 字段同样会被忽略（防越权声明）。
 */
public record RefreshRequest(String refreshToken, Set<String> roles) {
}
