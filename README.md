# 本地访问鉴权网关（access-gateway-java）

一套**本地可运行**的访问鉴权网关：身份、会话、密钥与策略数据全部保存在进程内，
不依赖任何外部服务或真实凭据。基于 Spring Boot 3 / Java 21，令牌为进程内实现的
类 JWT 结构（HMAC-SHA256 签名），无额外依赖。

## 快速开始

```bash
mvn spring-boot:run          # 启动，默认端口 8080
mvn test                     # 运行全部测试（28 个用例）
```

预置演示用户（仅本地模拟）：

| 用户  | 密码        | 角色            |
|-------|-------------|-----------------|
| alice | alice-pass  | reader          |
| bob   | bob-pass    | writer          |
| carol | carol-pass  | reader, writer  |
| admin | admin-pass  | admin           |

典型调用：

```bash
# 1. 登录（roles 字段会被忽略并记录警告，角色只以服务端身份库为准）
curl -s -X POST localhost:8080/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}'

# 2. 访问判定（roles 字段同样被忽略，判定只用令牌内角色）
curl -s -X POST localhost:8080/gateway/authorize -H 'Content-Type: application/json' \
  -d '{"accessToken":"<token>","resource":"/docs","action":"read"}'

# 3. 刷新（轮换）
curl -s -X POST localhost:8080/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refresh-token>"}'

# 4. 吊销会话族
curl -s -X POST localhost:8080/auth/revoke -H 'Content-Type: application/json' \
  -d '{"familyId":"fam-1"}'

# 5. 管理端点（本地演示用途，未加保护）
curl -s localhost:8080/admin/policies                 # 查看策略与版本
curl -s -X POST localhost:8080/admin/policies -H 'Content-Type: application/json' -d '[]'  # 热更新
curl -s -X POST localhost:8080/admin/keys/rotate      # 轮换签名密钥
curl -s localhost:8080/admin/keys                     # 查看密钥与重叠期
curl -s localhost:8080/admin/audit                    # 查看审计日志
```

## 令牌生命周期

令牌格式：`base64url(header).base64url(payload).base64url(HMAC-SHA256)`，
头部含 `kid`（签名密钥编号），载荷含 `iss/sub/aud/jti/typ/iat/nbf/exp/roles`。

1. **签发**：`POST /auth/login` 校验凭证后签发访问令牌（默认 300s）与刷新令牌
   （默认 3600s）。角色从身份库读取并写入访问令牌；刷新令牌不携带角色。
2. **使用**：`POST /gateway/authorize` 校验访问令牌后做策略判定。
   校验顺序固定：**格式 → kid 存在 → 签名 → 令牌类型 → iss → aud → 密钥重叠期 →
   nbf → exp**，任一失败即拒绝并返回可区分原因码
   （`MALFORMED / UNKNOWN_SIGNING_KEY / SIGNATURE_MISMATCH / ISSUER_MISMATCH /
   AUDIENCE_MISMATCH / KEY_OVERLAP_ENDED / NOT_YET_VALID / EXPIRED`）。
3. **时钟偏差**：有效期判定为闭区间 `[nbf - skew, exp + skew]`（skew 默认 30s，
   可配置）。边界上接受、边界外一秒拒绝；同一时刻重复校验结论一致。
4. **刷新**：`POST /auth/refresh` 校验刷新令牌后原子轮换，签发新令牌对；
   新访问令牌的角色重新读取身份库当前值。
5. **过期/吊销**：访问令牌自然过期；刷新令牌随会话族被轮换、重用检测或显式吊销。

## 刷新令牌轮换、重用检测与吊销规则

- 每次登录创建一个**会话族**（family），该次登录签发的所有刷新令牌属于同一族。
- 轮换是**原子**的：每个族一把监视器锁，同一刷新令牌被并发使用时，
  **有且仅有一次**成功；其余请求在临界区内发现令牌编号已轮换。
- **重用检测**：使用非当前编号的刷新令牌（即旧令牌重放）判定为重用，
  立即**整族吊销且不可恢复**——包括本次轮换刚签发的新令牌在内全部失效。
- **显式吊销**：`POST /auth/revoke` 按 familyId 吊销整族。
- 会话族有绝对有效期（登录时确定的 refreshTtl），刷新不能无限续期。
- 失败原因可区分：`INVALID_CREDENTIALS / INVALID_REFRESH_TOKEN /
  REFRESH_TOKEN_REVOKED / REFRESH_TOKEN_REUSED / FAMILY_NOT_FOUND`。

## 密钥轮换与重叠期

- 签名密钥由本地种子按 kid 派生（`HMAC-SHA256(seed, "key:"+kid)`），进程内保存。
- `POST /admin/keys/rotate` 生成新密钥并退役旧密钥；旧密钥进入**重叠接受期**
  （`gateway.key.overlap-seconds`，默认 600s）。
- 重叠期内旧密钥签署的、仍在有效期内的令牌**继续有效**；新令牌一律用新密钥签发。
- 重叠期结束（`now > rejectAfter`，边界含 `rejectAfter`）后，旧密钥令牌一律以
  `KEY_OVERLAP_ENDED` 拒绝；未知 kid 以 `UNKNOWN_SIGNING_KEY` 拒绝。

## 授权判定顺序与审计

判定顺序固定（`PolicyEngine`）：

1. 令牌不含角色 → **默认拒绝**；
2. 任一角色命中 DENY 策略 → **拒绝**（DENY 优先于 ALLOW）；
3. 任一角色命中 ALLOW 策略 → **允许**；
4. 无匹配 → **默认拒绝**。

- **默认拒绝**：未显式允许即拒绝。
- **热更新**：`POST /admin/policies` 整体替换策略集，版本号递增；
  后续请求立即使用新版本，无需重启。同一令牌在策略变更前后的结论差异，
  可通过判定结果中的 `policyVersion` 与 `matchedPolicyIds` 解释。
- **审计**：每次允许/拒绝都写入审计（`GET /admin/audit` 可查），
  记录主体、角色、资源、动作、结论、原因、命中策略与策略版本。
- **防伪造**：登录/刷新/判定请求体中的 `roles` 字段一律被忽略并记录警告；
  判定只使用签名令牌内的角色，角色注入与越权声明不会被接受。

## 可配置项（`application.properties`，前缀 `gateway`）

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `gateway.issuer` | `local-access-gateway` | 令牌签发方（iss） |
| `gateway.default-audience` | `demo-api` | 默认受众（aud） |
| `gateway.token.access-ttl-seconds` | `300` | 访问令牌有效期 |
| `gateway.token.refresh-ttl-seconds` | `3600` | 刷新令牌/会话族有效期 |
| `gateway.token.clock-skew-seconds` | `30` | 时钟偏差容忍（闭区间边界） |
| `gateway.key.overlap-seconds` | `600` | 旧密钥重叠接受期 |
| `gateway.key.seed` | 本地演示种子 | 派生 HMAC 密钥的种子，非真实凭据 |

## 验证方法

```bash
mvn test
```

| 测试类 | 覆盖场景 |
|--------|----------|
| `TokenCodecTest` | 合法往返、格式错误、载荷篡改、未知密钥、iss/aud 不匹配、类型混淆 |
| `RefreshTokenFlowTest` | 错误凭证、轮换、**16 线程并发刷新仅一次成功**、重用后整族吊销不可恢复、显式吊销、刷新令牌过期 |
| `KeyRotationTest` | 重叠期内旧令牌可用、新令牌用新密钥、重叠期边界（含边界接受/超一秒拒绝）、新密钥不受旧重叠期影响 |
| `ClockSkewBoundaryTest` | exp/nbf 两个方向的容忍边界（边界接受、外一秒拒绝）、同一时刻重复校验结论稳定、容忍值可配置 |
| `PolicyEngineTest` | 默认拒绝、空角色拒绝、ALLOW 命中、DENY 优先、热更新立即生效且同版本结论一致 |
| `GatewayWebTest` | 端到端：角色注入被忽略、篡改/格式错误 401 且原因可区分、错误凭证 401、HTTP 热更新后判定翻转并留审计 |
| `ApplicationTests` | Spring 上下文加载 |

所有用例在日志中打印**输入**与**判定依据**（原因码、命中策略、策略版本等），
可用 `mvn test -Dtest=<类名>` 单独复现。时钟相关用例使用可控时钟
（`tests/support/TestClock`），结果确定且可复现。
