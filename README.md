# Access Gateway（本地可运行的访问鉴权网关）

基于 Spring Boot 的进程内访问鉴权网关，用内存状态模拟身份、会话与策略数据，
不依赖任何外部服务或真实凭据。

## 运行与验证

```bash
mvn test          # 运行全部测试（39 个，日志打印输入与判定依据）
mvn spring-boot:run   # 本地启动，默认 8080 端口
```

端到端手工验证：

```bash
# 1. 凭证换令牌（内置用户：alice/alice-pass=reader, bob/bob-pass=reader+writer, admin/admin-pass=admin）
curl -s -X POST localhost:8080/auth/token -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob-pass"}'

# 2. 访问受保护资源
curl -s localhost:8080/api/documents -H "Authorization: Bearer <accessToken>"
curl -s -X POST localhost:8080/api/documents -H "Authorization: Bearer <accessToken>"

# 3. 刷新轮换 / 吊销
curl -s -X POST localhost:8080/auth/refresh -H 'Content-Type: application/json' -d '{"refreshToken":"<rt>"}'
curl -s -X POST localhost:8080/auth/revoke  -H 'Content-Type: application/json' -d '{"refreshToken":"<rt>"}'

# 4. 管理端点：策略热更新、密钥轮换、审计查询
curl -s -X PUT localhost:8080/admin/policies -H 'Content-Type: application/json' \
  -d '[{"role":"writer","resource":"documents","action":"write","allow":true}]'
curl -s -X POST localhost:8080/admin/keys/rotate
curl -s localhost:8080/admin/audit
curl -s 'localhost:8080/admin/audit?subject=alice&allowed=false&eventType=ACCESS&from=2026-10-07T00:00:00Z&to=2026-10-08T00:00:00Z'

# 5. 会话管理：查看自己的活跃会话 / 下线单个 / 下线全部
curl -s localhost:8080/auth/sessions -H "Authorization: Bearer <accessToken>"
curl -s -X DELETE localhost:8080/auth/sessions/<sessionId> -H "Authorization: Bearer <accessToken>"
curl -s -X DELETE localhost:8080/auth/sessions -H "Authorization: Bearer <accessToken>"
```

## 令牌生命周期

### 访问令牌（HMAC-SHA256，header.payload.signature）

- 由 `POST /auth/token`（凭证校验通过）或 `POST /auth/refresh` 签发，默认有效期 15 分钟。
- 声明：`sub`（用户）、`roles`（角色，**只能来自服务端用户档案**，客户端无法注入）、
  `iss`、`aud`、`iat`、`exp`、`fam`（会话族）、头部 `kid`（签名密钥标识）。
- 校验失败原因可区分（`TokenFailureReason`）：
  `MALFORMED`（格式非法）、`BAD_SIGNATURE`（篡改）、`UNKNOWN_KEY`（kid 不存在）、
  `KEY_RETIRED`（密钥重叠期已过）、`ISSUER_MISMATCH`、`AUDIENCE_MISMATCH`、
  `EXPIRED`、`NOT_YET_VALID`、`SESSION_REVOKED`（令牌本身合法但所属会话已被下线）。

### 时钟偏差容忍边界（确定且可复现）

设容忍边界为 `skew`（`gateway.clock-skew-tolerance`，默认 60 秒）：

- 过期判定：`now > exp + skew` → `EXPIRED`；`now <= exp + skew`（含边界）视为有效。
- 未生效判定：`now < iat - skew` → `NOT_YET_VALID`；`now >= iat - skew`（含边界）视为有效。

边界上/边界外 1 秒的结论由 `JwtServiceTest` 用可推进时钟确定性验证，重复判定结论一致。

### 刷新令牌（不透明随机串）

- **轮换**：每次 `POST /auth/refresh` 消耗旧刷新令牌并签发新令牌对（同一会话族 `fam`）。
- **重用检测**：已消耗的令牌再次被使用 → 整个会话族立即吊销且**不可恢复**，
  返回 `ALREADY_USED_REUSE_DETECTED`（HTTP 403）；族内其他令牌（含刚轮换出的新令牌）
  此后一律返回 `FAMILY_REVOKED`。
- **并发安全**：令牌消耗通过 CAS 原子完成，同一刷新令牌被并发使用时有且仅有一次成功，
  其余全部失败（重用检测或族吊销，原因可区分）。
- **吊销**：`POST /auth/revoke` 显式吊销会话族；过期返回 `EXPIRED`，未知令牌返回 `UNKNOWN_TOKEN`。

### 会话续期上限（闲置超时与总上限）

除单次刷新令牌自身的时效外，每个会话族还有两道续期边界（判定规则与过期判定一致：
`now > 边界` 才失效，边界上仍有效，边界上/外 1 秒结论确定可复现）：

- **闲置超时**（`gateway.session-idle-timeout`，默认 24h）：最近一次刷新活动
  （建立或成功轮换）超过该时长后，族内任何刷新令牌换发失败，返回 `SESSION_IDLE_TIMEOUT`。
- **总最长可续期时间**（`gateway.session-max-lifetime`，默认 7d）：自会话建立起，
  即使一直连续轮换也不能无限续命；超过后返回 `SESSION_MAX_LIFETIME_EXCEEDED`。

失败原因可与 `FAMILY_REVOKED`（吊销）、`EXPIRED`（单令牌过期）明确区分。
会话状态（建立时间、最近活动时间、是否吊销）由 `SessionRegistry` 统一维护。

### 密钥轮换与重叠期

- `POST /admin/keys/rotate` 生成新签名密钥，旧密钥进入重叠期
  （`retiredAt = 轮换时刻 + gateway.key-overlap-period`，默认 30 分钟）。
- 重叠期内：旧密钥签发的、自身仍在有效期内的令牌**继续有效**（不因轮换失效）。
- 重叠期结束后：旧密钥令牌一律以 `KEY_RETIRED` 拒绝；未知 `kid` 以 `UNKNOWN_KEY` 拒绝。
- 新密钥签发的令牌轮换后立即可用；多次轮换时各旧密钥按各自重叠期独立计时。

## 会话管理（用户视角）

凭本人访问令牌（Bearer）操作，响应只含建立时间、最近活动时间与状态，不暴露任何凭据：

- `GET /auth/sessions`：列出当前用户的活跃会话（`sessionId`、`createdAt`、
  `lastActivityAt`、`status`）。
- `DELETE /auth/sessions/{sessionId}`：下线指定会话（仅限本人；他人或不存在的会话
  一律 404 `SESSION_NOT_FOUND`）。
- `DELETE /auth/sessions`：一次性下线当前用户的全部会话（含发起请求的会话本身）。

语义：

- 被下线的会话，其访问令牌**立即**以 `SESSION_REVOKED` 拒绝——即使签名与时效都正常；
  该原因与令牌非法（`MALFORMED`/`BAD_SIGNATURE`）、过期（`EXPIRED`）、
  签发方/受众不匹配（`ISSUER_MISMATCH`/`AUDIENCE_MISMATCH`）等明确区分。
- 同一条令牌重复请求结论一致；会话之间互不影响，除非明确选择全部下线。
- 下线与并发刷新同时发生时结果确定：刷新至多成功一次；无论竞争结果如何，
  会话最终处于吊销态，该会话的一切访问令牌（含竞争中刚签出的）立即失效，
  该会话族的任何刷新令牌此后一律 `FAMILY_REVOKED`。

## 审计

- 进入审计的动作：资源访问判定（`ACCESS`）、会话建立（`SESSION_ESTABLISHED`）、
  刷新轮换（`SESSION_REFRESHED`，成功与失败都记录，失败原因写入 `reason`）、
  主动下线/踢人（`SESSION_TERMINATED`）、刷新令牌重用检测（`REFRESH_REUSE_DETECTED`）。
- 每条记录携带：单调 `sequence`、时间 `at`、`eventType`、`subject`、`sessionId`、
  `roles`、`resource`、`action`、`allowed`、`reason`（判定依据，可解释放行/拒绝）。
- **容量上限**：`gateway.audit-capacity`（默认 10000），达到上限后按最旧优先淘汰；
  淘汰后剩余记录按 `sequence` 稳定升序。写入与查询并发安全（高并发下不丢、不乱、不报错）。
- **查询**：`GET /admin/audit`，查询参数均可空并任意组合：
  `subject`、`sessionId`、`allowed`（true/false）、`eventType`、
  `from`/`to`（ISO-8601 时间，闭区间）。

## 授权判定顺序

`ResourceController.guard` 对每次请求按固定顺序判定：

1. **Bearer 令牌存在性**：缺失 → 401 `MISSING_BEARER_TOKEN`。
2. **令牌校验**：失败 → 401 + 上述可区分原因。
3. **策略判定**（`PolicyEngine`）：逐条匹配允许策略（角色/资源/动作，支持 `*` 通配），
   任一命中即允许；**默认拒绝**。判定结果携带命中策略或拒绝原因，可解释。
4. **审计留痕**：允许与拒绝都写入 `AuditLog`（时间、主体、角色、资源、动作、结论、判定依据），
   可通过 `GET /admin/audit` 查询。

策略热更新：`PUT /admin/policies` 原子替换策略表，后续请求立即生效，无需重启；
令牌合法但策略已变更时，同一令牌同一策略下重复请求结论一致。

伪造防护：角色只来自服务端 `CredentialStore` 档案；篡改令牌中的角色声明会导致
`BAD_SIGNATURE`；令牌请求报文中不包含也无法指定角色。

## 可配置项（`application.properties`，前缀 `gateway.`）

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `gateway.issuer` | `access-gateway` | 令牌签发方（iss） |
| `gateway.audience` | `gateway-clients` | 令牌受众（aud） |
| `gateway.access-token-ttl` | `15m` | 访问令牌有效期 |
| `gateway.refresh-token-ttl` | `12h` | 刷新令牌有效期 |
| `gateway.clock-skew-tolerance` | `60s` | 客户端/服务端时钟偏差容忍边界 |
| `gateway.key-overlap-period` | `30m` | 密钥轮换后旧密钥的验签重叠期 |
| `gateway.session-max-lifetime` | `7d` | 会话自建立起的总最长可续期时间 |
| `gateway.session-idle-timeout` | `24h` | 会话闲置超时（无刷新活动即失效） |
| `gateway.audit-capacity` | `10000` | 审计日志容量上限（最旧优先淘汰） |

## 与现有行为的兼容范围

- 登录、刷新轮换、重用检测、显式吊销、密钥重叠期、时钟偏差容忍、策略判定与热更新
  的既有语义全部保持不变（既有 24 个测试原样通过）。
- 新增行为只叠加在既有链路之上：访问令牌校验在全部内在检查通过后追加会话吊销检查；
  刷新轮换在既有检查（未知/吊销/过期）之后追加闲置与总上限检查。
- 重用检测触发族吊销后，该族访问令牌现在会立即以 `SESSION_REVOKED` 失效
  （此前仅刷新令牌被拒），属于安全加固。
- 进程重启后会话注册表与审计日志清空：重启前签发的访问令牌视为“未知会话”，
  在其自身有效期内仍然有效；刷新令牌本就不跨重启保留。

## 测试覆盖

| 测试类 | 覆盖场景 |
|---|---|
| `JwtServiceTest` | 篡改令牌、iss/aud 不匹配、格式非法、时钟偏差边界（exp/iat 两侧，边界上/外 1 秒） |
| `RefreshTokenServiceTest` | 16 线程并发刷新仅一次成功、重用检测后族不可恢复、显式吊销、过期、未知令牌、正常轮换链 |
| `KeyRotationTest` | 重叠期内旧令牌有效、重叠期后 `KEY_RETIRED`、未知 `kid`、连续两次轮换 |
| `PolicyAndAuditTest` | 默认拒绝、策略热更新即时生效且结论一致、审计留痕、角色注入不可能、越权声明被拒 |
| `SessionManagementTest` | 活跃会话列表（时间/状态/不含凭据）、单会话下线与全部下线、被下线令牌立即失效且原因可区分、并发下线+刷新的确定终态 |
| `SessionRenewalLimitTest` | 闲置超时与总上限的边界上/外 1 秒、连续轮换不能无限续命、失败原因可区分、重用检测不受影响 |
| `AuditLogTest` | 审计筛选（主体/会话/结论/事件类型/时间范围）、容量最旧优先淘汰且顺序稳定、16 线程高并发写入不丢不乱、条目可追溯 |
| `SessionEndpointsHttpTest` | 真实 HTTP：登录x2→会话列表→单会话下线→令牌立即失效→审计筛选→全部下线 |
| `GatewayApplicationTest` | 真实 HTTP 端到端：错误凭证→签发→访问→刷新→重用检测 |

所有单测日志均打印输入与判定依据（`输入=... 判定依据=... 结论=...`）。
