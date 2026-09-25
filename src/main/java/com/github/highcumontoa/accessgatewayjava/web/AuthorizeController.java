package com.github.highcumontoa.accessgatewayjava.web;

import com.github.highcumontoa.accessgatewayjava.audit.AuditEvent;
import com.github.highcumontoa.accessgatewayjava.audit.AuditService;
import com.github.highcumontoa.accessgatewayjava.config.GatewayProperties;
import com.github.highcumontoa.accessgatewayjava.policy.Decision;
import com.github.highcumontoa.accessgatewayjava.policy.PolicyEngine;
import com.github.highcumontoa.accessgatewayjava.token.TokenCodec;
import com.github.highcumontoa.accessgatewayjava.token.VerifiedToken;
import com.github.highcumontoa.accessgatewayjava.web.dto.AuthorizeRequest;
import com.github.highcumontoa.accessgatewayjava.web.dto.AuthorizeResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;

/**
 * 访问判定端点：先验令牌，再做策略判定，最后写审计。
 * 角色只取自校验通过的令牌，请求体中的 roles 一律忽略。
 */
@RestController
@RequestMapping("/gateway")
public class AuthorizeController {

    private static final Logger log = LoggerFactory.getLogger(AuthorizeController.class);

    private final TokenCodec codec;
    private final PolicyEngine engine;
    private final AuditService audit;
    private final GatewayProperties props;
    private final Clock clock;

    public AuthorizeController(TokenCodec codec, PolicyEngine engine, AuditService audit,
                               GatewayProperties props, Clock clock) {
        this.codec = codec;
        this.engine = engine;
        this.audit = audit;
        this.props = props;
        this.clock = clock;
    }

    @PostMapping("/authorize")
    public AuthorizeResponse authorize(@RequestBody AuthorizeRequest request) {
        if (request.roles() != null && !request.roles().isEmpty()) {
            log.warn("忽略访问判定请求中客户端自报角色 {}", request.roles());
        }
        String expectedAudience = (request.audience() == null || request.audience().isBlank())
                ? props.getDefaultAudience() : request.audience();

        VerifiedToken verified = codec.verify(request.accessToken(), TokenCodec.TYPE_ACCESS, expectedAudience);
        Decision decision = engine.decide(verified.claims().getRoles(), request.resource(), request.action());

        audit.record(new AuditEvent(clock.instant(), verified.claims().getSubject(),
                verified.claims().getRoles(), request.resource(), request.action(),
                decision.allowed(), decision.reason(), decision.matchedPolicyIds(),
                decision.policyVersion()));

        return new AuthorizeResponse(decision.allowed(), decision.reason(), decision.matchedPolicyIds(),
                decision.policyVersion(), verified.claims().getSubject(), verified.claims().getRoles());
    }
}
