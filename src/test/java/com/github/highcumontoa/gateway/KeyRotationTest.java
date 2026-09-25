package com.github.highcumontoa.gateway;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import com.github.highcumontoa.gateway.config.GatewayProperties;
import com.github.highcumontoa.gateway.support.MutableClock;
import com.github.highcumontoa.gateway.token.JwtService;
import com.github.highcumontoa.gateway.token.KeyManager;
import com.github.highcumontoa.gateway.token.TokenFailureReason;
import com.github.highcumontoa.gateway.token.TokenValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

class KeyRotationTest {
    private static final Logger log = LoggerFactory.getLogger(KeyRotationTest.class);

    private GatewayProperties properties;
    private MutableClock clock;
    private KeyManager keyManager;
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        properties = new GatewayProperties();
        properties.setKeyOverlapPeriod(Duration.ofMinutes(30));
        clock = new MutableClock(Instant.parse("2026-09-25T00:00:00Z"));
        keyManager = new KeyManager(properties, clock);
        jwtService = new JwtService(properties, keyManager, clock);
    }

    @Test
    void oldKeyTokenSurvivesOverlapButRejectedAfter() {
        String oldKeyId = keyManager.currentKey().keyId();
        String oldToken = jwtService.issue("alice", List.of("reader"), "fam-1");

        keyManager.rotate();
        assertNotEquals(oldKeyId, keyManager.currentKey().keyId());

        // 重叠期内：旧密钥签发的未过期令牌必须仍然有效
        clock.advance(Duration.ofMinutes(10));
        TokenValidationResult duringOverlap = jwtService.validate(oldToken);
        log.info("输入=轮换后重叠期内旧令牌, 判定依据=旧密钥retiredAt未到且令牌未过期, 结论={}", duringOverlap.isValid());
        assertTrue(duringOverlap.isValid());

        // 重叠期结束（令牌自身仍在有效期内：exp=15min，overlap=30min）
        clock.advance(Duration.ofMinutes(21)); // 总计31min > overlap
        TokenValidationResult afterOverlap = jwtService.validate(oldToken);
        log.info("输入=重叠期结束后旧令牌, 判定依据=旧密钥已退役(retiredAt已过), 结论={}", afterOverlap.failureReason());
        assertEquals(TokenFailureReason.KEY_RETIRED, afterOverlap.failureReason());
        // 结论稳定可复现
        assertEquals(TokenFailureReason.KEY_RETIRED, jwtService.validate(oldToken).failureReason());
    }

    @Test
    void newKeyTokensWorkImmediatelyAfterRotation() {
        keyManager.rotate();
        String token = jwtService.issue("bob", List.of("writer"), "fam-2");
        TokenValidationResult result = jwtService.validate(token);
        log.info("输入=轮换后新密钥签发的令牌, 判定依据=当前密钥验签通过, 结论={}", result.isValid());
        assertTrue(result.isValid());
    }

    @Test
    void unknownKeyIdRejected() {
        String token = jwtService.issue("alice", List.of("reader"), "fam-1");
        String[] parts = token.split("\\.");
        String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]))
                .replace(keyManager.currentKey().keyId(), "key-999");
        String forged = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(header.getBytes()) + "." + parts[1] + "." + parts[2];
        TokenValidationResult result = jwtService.validate(forged);
        log.info("输入=kid=key-999的令牌, 判定依据=kid不存在于密钥库, 结论={}", result.failureReason());
        assertEquals(TokenFailureReason.UNKNOWN_KEY, result.failureReason());
    }

    @Test
    void doubleRotationKeepsBothOverlappingKeysUsable() {
        String token1 = jwtService.issue("alice", List.of("reader"), "fam-1");
        keyManager.rotate();
        String token2 = jwtService.issue("alice", List.of("reader"), "fam-1");
        keyManager.rotate();

        clock.advance(Duration.ofMinutes(5));
        TokenValidationResult r1 = jwtService.validate(token1);
        TokenValidationResult r2 = jwtService.validate(token2);
        log.info("输入=两次轮换后两个旧令牌, 判定依据=两把旧密钥均在各自重叠期内, 结论=token1:{}, token2:{}",
                r1.isValid(), r2.isValid());
        assertTrue(r1.isValid());
        assertTrue(r2.isValid());
    }
}
