package com.github.highcumontoa.accessgatewayjava.auth;

import java.time.Instant;

/**
 * 一次成功认证/刷新签发的令牌对。
 */
public record IssuedTokens(String accessToken, Instant accessExpiresAt,
                           String refreshToken, Instant refreshExpiresAt,
                           String familyId) {
}
