package com.github.highcumontoa.gateway.token;

import java.time.Instant;

/** 签名密钥：retiredAt 之前可用于验签（重叠期），之后必须拒绝。 */
public record SigningKey(String keyId, byte[] secret, Instant createdAt, Instant retiredAt) {
    public boolean usableForVerify(Instant now) {
        return retiredAt == null || now.isBefore(retiredAt);
    }
    public SigningKey retiredAt(Instant when) {
        return new SigningKey(keyId, secret, createdAt, when);
    }
}
