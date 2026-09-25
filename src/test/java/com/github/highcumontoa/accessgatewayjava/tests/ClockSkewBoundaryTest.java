package com.github.highcumontoa.accessgatewayjava.tests;

import com.github.highcumontoa.accessgatewayjava.auth.IssuedTokens;
import com.github.highcumontoa.accessgatewayjava.token.TokenCodec;
import com.github.highcumontoa.accessgatewayjava.token.TokenException;
import com.github.highcumontoa.accessgatewayjava.token.TokenRejectReason;
import com.github.highcumontoa.accessgatewayjava.tests.support.TestGateway;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 时钟偏差容忍边界：容忍区间为闭区间 [nbf - skew, exp + skew]。
 * 边界上接受、边界外一秒拒绝；同一时刻重复校验结论一致（稳定可复现）。
 */
class ClockSkewBoundaryTest {

    private static final Logger log = LoggerFactory.getLogger(ClockSkewBoundaryTest.class);

    private static final Instant T0 = Instant.parse("2026-09-25T10:00:00Z");

    @Test
    void expiryBoundaryIsInclusiveAndStable() {
        TestGateway gw = TestGateway.create();
        IssuedTokens tokens = gw.auth.login("alice", "alice-pass", "demo-api");
        long skew = gw.props.getToken().getClockSkewSeconds();
        long ttl = gw.props.getToken().getAccessTtlSeconds();
        log.info("输入: 访问令牌 exp=T0+{}s, 时钟偏差容忍={}s（闭区间）", ttl, skew);

        Instant onBoundary = T0.plusSeconds(ttl + skew);
        gw.clock.setInstant(onBoundary);
        assertDoesNotThrow(() -> gw.codec.verify(tokens.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api"));
        assertDoesNotThrow(() -> gw.codec.verify(tokens.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api"));
        log.info("判定依据: now=exp+skew={} 边界上接受，重复校验结论一致", onBoundary);

        Instant beyond = T0.plusSeconds(ttl + skew + 1);
        gw.clock.setInstant(beyond);
        TokenException ex = assertThrows(TokenException.class,
                () -> gw.codec.verify(tokens.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api"));
        log.info("判定依据: now=exp+skew+1s={} 边界外拒绝 reason={}", beyond, ex.getReason());
        assertEquals(TokenRejectReason.EXPIRED, ex.getReason());

        gw.clock.setInstant(beyond);
        TokenException ex2 = assertThrows(TokenException.class,
                () -> gw.codec.verify(tokens.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api"));
        assertEquals(ex.getReason(), ex2.getReason());
        log.info("判定依据: 同一时刻重复校验 reason={} 结论稳定", ex2.getReason());
    }

    @Test
    void notYetValidBoundaryIsInclusiveAndStable() {
        TestGateway gw = TestGateway.create();
        IssuedTokens tokens = gw.auth.login("alice", "alice-pass", "demo-api");
        long skew = gw.props.getToken().getClockSkewSeconds();
        log.info("输入: 访问令牌 nbf=T0, 模拟客户端时钟快于服务端（now 早于 nbf），容忍={}s", skew);

        Instant onBoundary = T0.minusSeconds(skew);
        gw.clock.setInstant(onBoundary);
        assertDoesNotThrow(() -> gw.codec.verify(tokens.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api"));
        assertDoesNotThrow(() -> gw.codec.verify(tokens.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api"));
        log.info("判定依据: now=nbf-skew={} 边界上接受，重复校验结论一致", onBoundary);

        Instant beyond = T0.minusSeconds(skew + 1);
        gw.clock.setInstant(beyond);
        TokenException ex = assertThrows(TokenException.class,
                () -> gw.codec.verify(tokens.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api"));
        log.info("判定依据: now=nbf-skew-1s={} 边界外拒绝 reason={}", beyond, ex.getReason());
        assertEquals(TokenRejectReason.NOT_YET_VALID, ex.getReason());

        gw.clock.setInstant(beyond);
        TokenException ex2 = assertThrows(TokenException.class,
                () -> gw.codec.verify(tokens.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api"));
        assertEquals(ex.getReason(), ex2.getReason());
        log.info("判定依据: 同一时刻重复校验 reason={} 结论稳定", ex2.getReason());
    }

    @Test
    void skewIsConfigurable() {
        TestGateway gw = TestGateway.create(p -> p.getToken().setClockSkewSeconds(5));
        IssuedTokens tokens = gw.auth.login("alice", "alice-pass", "demo-api");
        long ttl = gw.props.getToken().getAccessTtlSeconds();
        log.info("输入: 自定义容忍=5s, exp=T0+{}s", ttl);

        gw.clock.setInstant(T0.plusSeconds(ttl + 5));
        assertDoesNotThrow(() -> gw.codec.verify(tokens.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api"));
        log.info("判定依据: now=exp+5s 边界上接受");

        gw.clock.setInstant(T0.plusSeconds(ttl + 6));
        TokenException ex = assertThrows(TokenException.class,
                () -> gw.codec.verify(tokens.accessToken(), TokenCodec.TYPE_ACCESS, "demo-api"));
        log.info("判定依据: now=exp+6s 拒绝 reason={}", ex.getReason());
        assertEquals(TokenRejectReason.EXPIRED, ex.getReason());
    }
}
