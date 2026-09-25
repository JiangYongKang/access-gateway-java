package com.github.highcumontoa.accessgatewayjava.web.dto;

import java.time.Instant;

/**
 * 令牌对响应。
 */
public record TokenResponse(String accessToken, Instant accessExpiresAt,
                            String refreshToken, Instant refreshExpiresAt,
                            String familyId, String tokenType) {
}
