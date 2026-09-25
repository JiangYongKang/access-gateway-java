package com.github.highcumontoa.gateway.token;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import org.springframework.stereotype.Component;

/**
 * 进程内密钥管理。
 * 轮换时旧密钥进入重叠期（retiredAt = 轮换时刻 + keyOverlapPeriod），
 * 重叠期内旧密钥签发的未过期令牌仍可验签；重叠期结束后验签返回 KEY_RETIRED。
 */
@Component
public class KeyManager {
    private final GatewayProperties properties;
    private final Clock clock;
    private final CopyOnWriteArrayList<SigningKey> keys = new CopyOnWriteArrayList<>();
    private final AtomicInteger sequence = new AtomicInteger();
    private final SecureRandom random = new SecureRandom();

    public KeyManager(GatewayProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
        keys.add(newKey());
    }

    private SigningKey newKey() {
        byte[] secret = new byte[32];
        random.nextBytes(secret);
        return new SigningKey("key-" + sequence.incrementAndGet(), secret, Instant.now(clock), null);
    }

    /** 当前签名密钥（列表末尾）。 */
    public SigningKey currentKey() {
        return keys.get(keys.size() - 1);
    }

    /**
     * 按 kid 查找验签密钥；重叠期已过的密钥返回 null（调用方据此区分 KEY_RETIRED）。
     */
    public SigningKey findForVerify(String keyId) {
        Instant now = Instant.now(clock);
        for (SigningKey key : keys) {
            if (key.keyId().equals(keyId)) {
                return key.usableForVerify(now) ? key : null;
            }
        }
        return null;
    }

    /** 是否存在该 kid（含已退役），用于区分 UNKNOWN_KEY 与 KEY_RETIRED。 */
    public boolean knownKeyId(String keyId) {
        return keys.stream().anyMatch(k -> k.keyId().equals(keyId));
    }

    /** 轮换：生成新密钥，旧密钥在重叠期结束后退役。 */
    public synchronized SigningKey rotate() {
        Instant retireAt = Instant.now(clock).plus(properties.getKeyOverlapPeriod());
        SigningKey oldKey = currentKey();
        keys.replaceAll(k -> k.keyId().equals(oldKey.keyId()) ? k.retiredAt(retireAt) : k);
        SigningKey fresh = newKey();
        keys.add(fresh);
        return fresh;
    }

    public List<SigningKey> allKeys() {
        return List.copyOf(keys);
    }
}
