package com.github.highcumontoa.accessgatewayjava.token;

/**
 * 访问令牌被拒绝的可区分原因码。
 */
public enum TokenRejectReason {
    /** 格式错误：段数、Base64URL、JSON 或头部字段不合法。 */
    MALFORMED,
    /** 令牌头部 kid 不在密钥库（含未知/已彻底删除）。 */
    UNKNOWN_SIGNING_KEY,
    /** 签名不匹配：载荷或头部被篡改。 */
    SIGNATURE_MISMATCH,
    /** 签发方（iss）与网关期望不一致。 */
    ISSUER_MISMATCH,
    /** 受众（aud）与本次请求期望不一致。 */
    AUDIENCE_MISMATCH,
    /** 签名密钥已轮换，且重叠接受期已结束。 */
    KEY_OVERLAP_ENDED,
    /** 尚在 nbf 之前（已计入时钟偏差容忍）。 */
    NOT_YET_VALID,
    /** 已过 exp（已计入时钟偏差容忍）。 */
    EXPIRED
}
