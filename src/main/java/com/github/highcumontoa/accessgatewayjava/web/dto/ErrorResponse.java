package com.github.highcumontoa.accessgatewayjava.web.dto;

import java.time.Instant;

/**
 * 统一错误响应：原因码可区分。
 */
public record ErrorResponse(String error, String message, Instant at) {
}
