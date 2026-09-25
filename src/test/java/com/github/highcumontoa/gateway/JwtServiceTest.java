package com.github.highcumontoa.gateway;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
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

class JwtServiceTest {
    private static final Logger log = LoggerFactory.getLogger(JwtServiceTest.class);
    private static final Duration SKEW = Duration.ofSeconds(60);

    private GatewayProperties properties;
    private MutableClock clock;
    private KeyManager keyManager;
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        properties = new GatewayProperties();
        properties.setClockSkewTolerance(SKEW);
        clock = new MutableClock(Instant.parse("2026-09-25T00:00:00Z"));
        keyManager = new KeyManager(properties, clock);
        jwtService = new JwtService(properties, keyManager, clock);
    }

    @Test
    void validTokenPasses() {
        String token = jwtService.issue("alice", List.of("reader"), "fam-1");
        TokenValidationResult result = jwtService.validate(token);
        log.info("输入=合法令牌, 判定依据={}, 结论={}", "签名校验通过且 iss/aud/exp 均匹配", result);
        assertTrue(result.isValid());
        assertEquals("alice", result.claims().subject());
        assertEquals(List.of("reader"), result.claims().roles());
    }

    @Test
    void tamperedTokenRejectedWithBadSignature() {
        String token = jwtService.issue("alice", List.of("reader"), "fam-1");
        // 篡改 payload：把 alice 改成 admin 并伪造角色
        String[] parts = token.split("\\.");
        String forged = new String(Base64.getUrlDecoder().decode(parts[1]))
                .replace("alice", "admin").replace("reader", "admin");
        String tampered = parts[0] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(forged.getBytes())
                + "." + parts[2];
        TokenValidationResult result = jwtService.validate(tampered);
        log.info("输入=篡改payload的令牌(伪造sub与roles), 判定依据=签名与内容不匹配, 结论={}", result.failureReason());
        assertEquals(TokenFailureReason.BAD_SIGNATURE, result.failureReason());
    }

    @Test
    void malformedTokenRejected() {
        TokenValidationResult result = jwtService.validate("not-a-token");
        log.info("输入=格式非法令牌, 判定依据=段数不为3, 结论={}", result.failureReason());
        assertEquals(TokenFailureReason.MALFORMED, result.failureReason());
    }

    @Test
    void issuerMismatchRejected() throws Exception {
        String token = jwtService.issue("alice", List.of("reader"), "fam-1");
        String[] parts = token.split("\\.");
        // 用同一密钥重签一个 iss 不同的令牌（模拟错误签发方）
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]))
                .replace(properties.getIssuer(), "evil-issuer");
        String resigned = resign(parts[0], payload);
        TokenValidationResult result = jwtService.validate(resigned);
        log.info("输入=iss=evil-issuer的令牌, 判定依据=iss与配置{}不一致, 结论={}",
                properties.getIssuer(), result.failureReason());
        assertEquals(TokenFailureReason.ISSUER_MISMATCH, result.failureReason());
    }

    @Test
    void audienceMismatchRejected() throws Exception {
        String token = jwtService.issue("alice", List.of("reader"), "fam-1");
        String[] parts = token.split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]))
                .replace(properties.getAudience(), "other-service");
        String resigned = resign(parts[0], payload);
        TokenValidationResult result = jwtService.validate(resigned);
        log.info("输入=aud=other-service的令牌, 判定依据=aud与配置{}不一致, 结论={}",
                properties.getAudience(), result.failureReason());
        assertEquals(TokenFailureReason.AUDIENCE_MISMATCH, result.failureReason());
    }

    @Test
    void clockSkewBoundaryIsDeterministic() {
        String token = jwtService.issue("alice", List.of("reader"), "fam-1");
        Duration ttl = properties.getAccessTokenTtl();

        // 边界内：exp + skew 整点仍有效（含边界）
        clock.advance(ttl.plus(SKEW));
        TokenValidationResult atBoundary = jwtService.validate(token);
        log.info("输入=now=exp+skew(边界上), 判定依据=now<=exp+skew视为有效, 结论={}", atBoundary.isValid());
        assertTrue(atBoundary.isValid());

        // 边界外 1 秒：必须过期，结论稳定
        clock.advance(Duration.ofSeconds(1));
        TokenValidationResult beyond = jwtService.validate(token);
        log.info("输入=now=exp+skew+1s(边界外), 判定依据=now>exp+skew, 结论={}", beyond.failureReason());
        assertEquals(TokenFailureReason.EXPIRED, beyond.failureReason());

        // 重复验证结论一致（可复现）
        assertEquals(TokenFailureReason.EXPIRED, jwtService.validate(token).failureReason());
    }

    @Test
    void notYetValidBoundary() {
        // 客户端时钟超前：iat 在未来
        String token = jwtService.issue("alice", List.of("reader"), "fam-1");
        clock.set(Instant.parse("2026-09-25T00:00:00Z").minus(SKEW)); // now = iat - skew，边界上
        TokenValidationResult atBoundary = jwtService.validate(token);
        log.info("输入=now=iat-skew(边界上), 判定依据=now>=iat-skew视为有效, 结论={}", atBoundary.isValid());
        assertTrue(atBoundary.isValid());

        clock.set(Instant.parse("2026-09-25T00:00:00Z").minus(SKEW).minusSeconds(1)); // 边界外
        TokenValidationResult beyond = jwtService.validate(token);
        log.info("输入=now=iat-skew-1s(边界外), 判定依据=now<iat-skew, 结论={}", beyond.failureReason());
        assertEquals(TokenFailureReason.NOT_YET_VALID, beyond.failureReason());
    }

    /** 用当前密钥对篡改后的 payload 重签（模拟持有错误声明但签名合法的令牌）。 */
    private String resign(String header, String payload) throws Exception {
        String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes());
        String unsigned = header + "." + encodedPayload;
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(keyManager.currentKey().secret(), "HmacSHA256"));
        return unsigned + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal(unsigned.getBytes()));
    }
}
