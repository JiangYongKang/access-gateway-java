package com.github.highcumontoa.accessgatewayjava.tests.support;

import com.github.highcumontoa.accessgatewayjava.audit.AuditService;
import com.github.highcumontoa.accessgatewayjava.auth.AuthService;
import com.github.highcumontoa.accessgatewayjava.auth.CredentialService;
import com.github.highcumontoa.accessgatewayjava.auth.SessionService;
import com.github.highcumontoa.accessgatewayjava.config.GatewayProperties;
import com.github.highcumontoa.accessgatewayjava.policy.PolicyEngine;
import com.github.highcumontoa.accessgatewayjava.policy.PolicyStore;
import com.github.highcumontoa.accessgatewayjava.token.KeyService;
import com.github.highcumontoa.accessgatewayjava.token.TokenCodec;

import java.time.Instant;

/**
 * 测试装配：用可控时钟把全部服务按生产一致的依赖关系连接起来。
 */
public class TestGateway {

    public final TestClock clock;
    public final GatewayProperties props;
    public final KeyService keyService;
    public final TokenCodec codec;
    public final CredentialService credentials;
    public final SessionService sessions;
    public final AuthService auth;
    public final PolicyStore policyStore;
    public final PolicyEngine engine;
    public final AuditService audit;

    private TestGateway(TestClock clock, GatewayProperties props) {
        this.clock = clock;
        this.props = props;
        this.keyService = new KeyService(props, clock);
        this.codec = new TokenCodec(props, keyService, clock);
        this.credentials = new CredentialService();
        this.sessions = new SessionService(props, clock);
        this.auth = new AuthService(credentials, sessions, codec, props, clock);
        this.policyStore = new PolicyStore();
        this.engine = new PolicyEngine(policyStore);
        this.audit = new AuditService();
    }

    public static TestGateway create() {
        GatewayProperties props = new GatewayProperties();
        return new TestGateway(TestClock.startAt(Instant.parse("2026-09-25T10:00:00Z")), props);
    }

    public static TestGateway create(java.util.function.Consumer<GatewayProperties> customizer) {
        GatewayProperties props = new GatewayProperties();
        customizer.accept(props);
        return new TestGateway(TestClock.startAt(Instant.parse("2026-09-25T10:00:00Z")), props);
    }
}
