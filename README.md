# Access Gateway（本地可运行的访问鉴权网关）

基于 Spring Boot 的进程内访问鉴权网关，用内存状态模拟身份、会话与策略数据，
不依赖任何外部服务或真实凭据。

## 运行与验证

```bash
mvn test          # 运行全部测试（39 个，日志打印输入与判定依据）
mvn package       # 一键打包，产出 target/access-gateway-java-1.0-SNAPSHOT.jar（可执行 fat jar）
mvn spring-boot:run   # 本地启动，默认 8080 端口
# 或：java -jar target/access-gateway-java-1.0-SNAPSHOT.jar
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

# 5. 会话自助管理（用自己的访问令牌识别身份）
curl -s localhost:8080/auth/sessions -H "Authorization: Bearer <accessToken>"
curl -s -X POST localhost:8080/auth/sessions/<sessionId>/terminate \
  -H "Authorization: Bearer <accessToken>"
curl -s -X POST localhost:8080/auth/sessions/terminate-all \
  -H "Authorization: Bearer <accessToken>"
```

## 令牌生命周期

### 访问令牌（HMAC-SHA256，header.payload.signature）

- 由 `POST /auth/token`（凭证校验通过）或 `POST /auth/refresh` 签发，默认有效期 15 分钟。
- 声明：`sub`（用户）、`roles`（角色，**只能来自服务端用户档案**，客户端无法注入）、
  `iss`、`aud`、`iat`、`exp`、`fam`（会话族）、头部 `kid`（签名密钥标识）。
- 校验失败原因可区分（`TokenFailureReason`）：
  `MALFORMED`（格式非法）、`BAD_SIGNATURE`（篡改）、`UNKNOWN_KEY`（kid 不存在）、
  `KEY_RETIRED`（密钥重叠期已过）、`ISSUER_MISMATCH`、`AUDIENCE_MISMATCH`、
  `EXPIRED`、`NOT_YET_VALID`、`SESSION_REVOKED`（令牌合法但所属会话已被下线/吊销）。

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

### 会话管理（谁的会话还活着、能活多久）

每次凭证换令牌成功都会建立一个**会话族**（即刷新令牌里的 `fam`，访问令牌声明 `fam` 指向它）。
会话与凭据分离存储，会话接口**只暴露元数据，绝不返回任何访问/刷新令牌**。

- **查看自己的会话**：`GET /auth/sessions`（携带本人访问令牌）。
  返回每个会话的 `sessionId`、`subject`、`createdAt`（建立时间）、`lastActivityAt`
  （最近一次刷新活动时间）、`state`（`ACTIVE` / `TERMINATED`）。
- **下线单个会话**：`POST /auth/sessions/{sessionId}/terminate`（204）。
  仅能下线属于自己的会话；归属他人返回 403 `SESSION_NOT_OWNED_BY_SUBJECT`，
  未知会话返回 404 `UNKNOWN_SESSION`，重复下线幂等成功。
- **一次性下线自己的全部会话**：`POST /auth/sessions/terminate-all`，返回本次终止数量。
- **下线立即生效**：被下线会话的访问令牌即使**签名与时效都完全正常**，也会立刻无法访问，
  资源接口与会话接口统一返回 401 `SESSION_REVOKED`，与令牌本身非法（`MALFORMED`/`BAD_SIGNATURE`）、
  `EXPIRED`、`ISSUER_MISMATCH`、`AUDIENCE_MISMATCH`、`UNKNOWN_KEY`、`KEY_RETIRED` 等原因**可区分**。
- **结论一致、会话隔离**：同一条令牌重复请求结论相同；下线一个会话不影响同主体的其他会话，
  也不影响其他主体；只有显式选择“全部下线”才会终止该主体的全部会话。

### 会话族续期上限（闲置超时 + 总寿命）

除单次刷新令牌自身的 `refresh-token-ttl` 外，每个会话族还有两条不可突破的时间边界，
判定与时钟偏差容忍一样**确定、可复现（含边界放行、边界外 1 秒拒绝）**：

- **总续期上限**（`gateway.session-max-lifetime`，默认 `7d`）：
  自会话建立起的最长可续期时间。即使连续不断轮换也不能无限续命；
  `now > createdAt + maxLifetime` 后，族内**任何**刷新令牌都无法换新，
  返回 `TOTAL_LIFETIME_REACHED`。
- **闲置超时**（`gateway.session-idle-timeout`，默认 `8h`）：
  `now > lastActivityAt + idleTimeout`（即距上一次成功刷新过久）后不能换新，
  返回 `IDLE_TIMEOUT`。每次成功轮换都会把 `lastActivityAt` 推进到轮换时刻。

刷新时的判定顺序（`SessionService`，同一把会话锁内原子完成）：

1. 令牌不存在 → `UNKNOWN_TOKEN`；
2. 会话已终止（下线/吊销/重用检测）→ `FAMILY_REVOKED`；
3. 单次刷新令牌已过期（`now > exp`）→ `EXPIRED`；
4. 超过总续期上限 → `TOTAL_LIFETIME_REACHED`；
5. 闲置超时 → `IDLE_TIMEOUT`；
6. 令牌已被消耗（并发竞争/重放，CAS 失败）→ 整族不可恢复吊销，`ALREADY_USED_REUSE_DETECTED`；
7. 否则轮换成功并推进活动时间。

说明：闲置/总寿命只阻止“用刷新令牌换发新令牌”，**不提前作废尚未到期的访问令牌**；
只有主动下线、显式吊销或重用检测才会让访问令牌立即失效（`SESSION_REVOKED`）。
三种刷新失败原因（`IDLE_TIMEOUT` / `TOTAL_LIFETIME_REACHED` / `FAMILY_REVOKED`）两两可区分，
边界判定由 `SessionLifetimeBoundaryTest` 用可推进时钟确定性验证。

### 下线与并发刷新

下线动作与刷新消耗在**同一个会话对象锁**内串行化，二者存在确定的先后（可线性化）：
刷新先拿到锁则该次换新成功、随后的下线让刚换出的令牌立刻 `FAMILY_REVOKED`；
下线先拿到锁则该次刷新直接 `FAMILY_REVOKED`。无论谁先，会话最终都处于不可恢复的终止态。
`SessionConcurrencyTest` 以 200 轮竞争验证两种顺序都会出现且结果自洽。

### 密钥轮换与重叠期

- `POST /admin/keys/rotate` 生成新签名密钥，旧密钥进入重叠期
  （`retiredAt = 轮换时刻 + gateway.key-overlap-period`，默认 30 分钟）。
- 重叠期内：旧密钥签发的、自身仍在有效期内的令牌**继续有效**（不因轮换失效）。
- 重叠期结束后：旧密钥令牌一律以 `KEY_RETIRED` 拒绝；未知 `kid` 以 `UNKNOWN_KEY` 拒绝。
- 新密钥签发的令牌轮换后立即可用；多次轮换时各旧密钥按各自重叠期独立计时。

## 审计事件、容量与查询

以下安全动作都会进入审计（`AuditAction`），每条记录带：单调递增 `sequence`、时间 `at`、
动作 `action`、主体 `subject`、会话 `sessionId`、结论 `outcome`、是否成功 `success`、明细 `detail`
（足以解释当时为什么放行或拒绝）。**记录中不含任何口令或令牌原文。**

- `SESSION_CREATED`：会话建立（凭证换令牌成功）；
- `REFRESH`：刷新轮换，成功或各类失败原因（`SUCCESS`/`EXPIRED`/`IDLE_TIMEOUT`/
  `MAX_LIFETIME`/`REUSE_DETECTED`/`REVOKED`/`UNKNOWN_TOKEN`）；
- `SESSION_TERMINATED`：主动下线单个会话 / 显式吊销（含跨主体拒绝）；
- `SESSIONS_TERMINATED_ALL`：一次性全部下线（含本次终止数量）；
- `RESOURCE_ACCESS`：受保护资源访问判定（`ALLOWED`/`DENIED`/被下线会话的 `REVOKED`）。

**容量上限**：`gateway.audit.max-entries`（默认 1000）。达到上限后**按最旧优先（FIFO）淘汰**；
淘汰后剩余记录仍按写入序号升序、顺序稳定。写入与淘汰在同一把锁内完成并分配序号，
查询在锁内复制快照，因此高并发写入/查询下**不丢记录、不乱序、不抛并发修改异常**
（见 `AuditCapacityAndQueryTest`：16 写者 × 500 条并发无丢失无乱序；并发读写不报错）。

**查询**：`GET /admin/audit` 支持以下可选查询参数（AND 关系，时间范围含端点）：

| 参数 | 含义 |
|---|---|
| `subject` | 按主体（用户名）筛选 |
| `sessionId` | 按会话族 id 筛选 |
| `action` | 按动作筛选，如 `REFRESH`、`SESSION_TERMINATED` |
| `outcome` | 按结论筛选，如 `IDLE_TIMEOUT`、`REUSE_DETECTED` |
| `from` / `to` | ISO-8601 时间范围（含端点） |

示例：

```bash
curl -s "localhost:8080/admin/audit?subject=alice&action=REFRESH&outcome=IDLE_TIMEOUT"
curl -s "localhost:8080/admin/audit?sessionId=<fam>&from=2026-10-01T00:00:00Z&to=2026-10-07T00:00:00Z"
```

## 授权判定顺序

`ResourceController.guard` 对每次请求按固定顺序判定：

1. **Bearer 令牌存在性**：缺失 → 401 `MISSING_BEARER_TOKEN`。
2. **令牌校验**：失败 → 401 + 上述可区分原因。
3. **会话守卫**：令牌合法但所属会话已被下线/吊销 → 401 `SESSION_REVOKED`。
4. **策略判定**（`PolicyEngine`）：逐条匹配允许策略（角色/资源/动作，支持 `*` 通配），
   任一命中即允许；**默认拒绝**。判定结果携带命中策略或拒绝原因，可解释。
5. **审计留痕**：允许与拒绝都写入 `AuditLog`（时间、主体、会话、动作、结论、判定依据），
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
| `gateway.session-max-lifetime` | `7d` | 会话族自建立起的总最长可续期时间（连续轮换也不能超过） |
| `gateway.session-idle-timeout` | `8h` | 会话族闲置超时：距上一次刷新活动超过该时长不能换新 |
| `gateway.audit.max-entries` | `1000` | 内存审计日志容量上限，达到后按最旧优先淘汰 |

> 新增配置在 `src/main/resources/application.properties` 中均有显式示例；删除该行即回落默认值。

## 与既有行为的兼容性

- 登录（凭证换令牌）、刷新轮换、刷新令牌重用检测、显式吊销、密钥轮换重叠期、时钟偏差边界、
  策略默认拒绝与热更新等既有行为**全部保持不变**（原有 24 个测试未改动且继续通过）。
- 会话族是对原有刷新令牌“族（fam）”概念的服务端落地；`RefreshTokenService` 的公开方法签名保留，
  其内部改为委托统一的 `SessionService`（同一把会话锁持有刷新记录与会话状态）。
- 既有审计构造方式（资源访问 7 字段、`reason()`/`allowed()` 访问器）保留兼容；
  新字段（序号/动作/会话/结论等）在其上扩展。
- 新增的会话守卫只在接入 `SessionService` 时生效；不改变令牌自身的签名与时效判定。
- 闲置/总寿命仅阻止换新令牌，不提前作废仍在有效期内的访问令牌；只有下线/吊销/重用才即时拦截访问。

## 测试覆盖

| 测试类 | 覆盖场景 |
|---|---|
| `JwtServiceTest` | 篡改令牌、iss/aud 不匹配、格式非法、时钟偏差边界（exp/iat 两侧，边界上/外 1 秒） |
| `RefreshTokenServiceTest` | 16 线程并发刷新仅一次成功、重用检测后族不可恢复、显式吊销、过期、未知令牌、正常轮换链 |
| `KeyRotationTest` | 重叠期内旧令牌有效、重叠期后 `KEY_RETIRED`、未知 `kid`、连续两次轮换 |
| `PolicyAndAuditTest` | 默认拒绝、策略热更新即时生效且结论一致、审计留痕、角色注入不可能、越权声明被拒 |
| `SessionManagementTest` | 会话列举不含凭据、单会话下线、全部下线、被下线访问令牌立即 `SESSION_REVOKED` 且原因可区分、重复请求结论一致、会话隔离、跨主体下线被拒 |
| `SessionLifetimeBoundaryTest` | 闲置超时与总续期上限在边界上放行/外 1 秒拒绝、连续轮换不能续命、吊销与超时原因可区分、闲置不提前作废访问令牌 |
| `SessionConcurrencyTest` | 下线与并发刷新同时发生时结果确定可线性化（200 轮竞争两种顺序均出现且自洽） |
| `AuditCapacityAndQueryTest` | 容量上限最旧淘汰、淘汰后顺序稳定、按主体/会话/动作/结论/时间范围筛选、16 写者高并发不丢不乱序、并发读写不报错 |
| `GatewayApplicationTest` | 真实 HTTP 端到端：错误凭证→签发→访问→刷新→重用检测；会话列举/下线/`SESSION_REVOKED`/全部下线/审计筛选 |

所有单测日志均打印输入与判定依据（`输入=... 判定依据=... 结论=...`）。

## 本地验证

```bash
mvn test                       # 39 个测试全部通过，日志打印输入/判定依据/结论
mvn package                    # 产出可执行 jar
java -jar target/access-gateway-java-1.0-SNAPSHOT.jar   # 启动（默认 8080）
```

打包后可按“运行与验证 / 端到端手工验证”中的 curl 步骤，依次验证：
会话列举不含凭据 → 下线单会话后其访问令牌立刻 `SESSION_REVOKED` 而其他会话仍 200 →
被下线会话刷新返回 `FAMILY_REVOKED` → 全部下线 → `/admin/audit` 按主体/动作筛选能查到下线事件。
（用可推进时钟的边界单测可确定性复现闲置/总寿命“边界上放行、边界外 1 秒拒绝”。）
