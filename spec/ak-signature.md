# AK 签名协议规范（Draft）

本文定义 `ak-auth-go` 在 `v1` 阶段的请求签名与验签规则。

## 1. 目标与边界

## 1.1 v1 目标

- 提供统一的 AK/SK 签名与验签协议
- 支持 `GET/POST/PUT/PATCH/DELETE`
- 提供可扩展的安全策略接口（Nonce、IP、权限）
- 签名算法面向接口实现，支持切换 `HMAC-SHA256`、`HMAC-SHA1`、`HMAC-SHA512`

## 1.2 非目标

- 不定义 AK 表结构
- 不管理 AK 生命周期（创建、禁用、轮换）
- 不内置 RBAC/ACL 业务模型

## 2. 术语

- `AK`：AccessKey ID（公开标识）
- `SK`：AccessKey Secret（私密密钥）
- `Canonical Request`：规范化后的请求表示
- `StringToSign`：待签名字符串

## 3. 请求头约定

## 3.1 必选头

- `Authorization`
- `Date`

## 3.2 可选头

- `Accept`
- `Content-Type`
- `Content-MD5`
- `x-acs-signature-nonce`（仅在启用 Nonce 防重放时要求）

## 3.3 Authorization 格式

```text
Authorization: acs <AccessKeyId>:<Signature>
```

示例：

```text
Authorization: acs test-ak:Q2hhbmdlTWVTaWduYXR1cmU=
```

说明：

- 前缀 `acs` 大小写不敏感，建议固定小写。
- `<AccessKeyId>` 与 `<Signature>` 之间用 `:` 分隔。

## 3.4 Date 格式

- 使用 RFC1123 GMT，例如：`Mon, 16 Mar 2026 10:30:00 GMT`
- 服务端默认校验时间窗口：`±15 分钟`（可通过 option 调整）

## 4. Canonical Request 规则

## 4.1 参与签名的组成

`StringToSign` 由以下字段按顺序拼接，并以 `\n` 分隔：

```text
HTTP-Method + "\n" +
Accept + "\n" +
Content-MD5 + "\n" +
Content-Type + "\n" +
Date + "\n" +
CanonicalizedHeaders +
CanonicalizedResource
```

说明：

- 缺失字段按空串处理（保留换行占位）。
- `CanonicalizedHeaders` 为空时直接省略内容（但前面的 `Date + "\n"` 保留）。

## 4.2 HTTP Method

- 取请求真实方法并转大写。
- `GET/POST/PUT/PATCH/DELETE` 全部支持。

## 4.3 Accept / Content-Type / Content-MD5

- 直接取请求头原值（建议客户端与服务端都做 `TrimSpace`）。
- 无该头时记为空串。
- `GET/DELETE` 无 body 时，`Content-MD5` 为空串（默认不强制）。
- `POST/PUT/PATCH` 有 body 时，建议提供 `Content-MD5`。

## 4.4 CanonicalizedHeaders

仅处理 `x-acs-` 前缀请求头（大小写不敏感），规则如下：

- header 名转小写
- header 值去除首尾空白，内部连续空白折叠为单个空格
- 同名 header 多值用 `,` 连接（按接收顺序）
- 按 header 名字典序升序排序
- 每行格式：`key:value\n`

示例：

```text
x-acs-signature-nonce:abc123
x-acs-trace-id:req-001
```

## 4.5 CanonicalizedResource

由 `Path + Query` 组成，规则如下：

- `Path`：使用请求路径，保证以 `/` 开头
- `Query`：
  - 包含所有查询参数（含重复 key）
  - 按 `key` 字典序排序；`key` 相同按 `value` 字典序排序
  - 按 RFC3986 编码（空格为 `%20`，不是 `+`）
  - 拼接格式：`k1=v1&k1=v2&k2=v3`
- 无查询参数时仅使用 `Path`

示例：

```text
/api/v1/resources?a=1&b=2
```

## 5. 签名算法（面向接口）

`v1` 的签名算法采用接口抽象，不写死具体实现。

建议接口（示意）：

```go
type SignatureAlgorithm interface {
    Name() string
    Sign(secret []byte, message []byte) ([]byte, error)
}
```

`v1` 内置实现：

- `HMAC-SHA256`（默认）
- `HMAC-SHA1`
- `HMAC-SHA512`

签名计算通式：

```text
Signature = Base64( Sign(SK, StringToSign) )
```

验签时要求：

- 使用常量时间比较避免时序攻击

## 6. 服务端验签流程

1. 解析 `Authorization`，提取 `AK` 与客户端签名
2. 通过 `SecretProvider` 获取该 `AK` 对应的 `SK` 与状态
3. 校验 `Date` 是否在允许窗口内
4. 根据配置选择签名算法（默认 `HMAC-SHA256`）
5. 构建 `StringToSign`
6. 计算服务端签名并与客户端签名常量时间比较
7. 若启用 `NonceStore`，执行 nonce 去重校验
8. 若启用 `IPPolicy`，执行来源 IP 校验
9. 若启用 `Authorizer`，执行权限 allow/deny 判断

说明：

- 默认只执行步骤 `1~6`（签名 + 时间窗口）
- 步骤 `7~9` 由 options 显式开启

## 7. 扩展接口（Options）

- `WithSignatureAlgorithm(alg SignatureAlgorithm)`
- `WithNonceStore(store NonceStore)`
- `WithIPPolicy(policy IPPolicy)`
- `WithAuthorizer(authorizer Authorizer)`
- `WithClockSkew(d time.Duration)`
- `WithRequiredHeaders(...)`（保留扩展）

## 8. 错误语义与 HTTP 状态码

建议错误码映射如下：

| 错误标识 | 含义 | HTTP |
|---|---|---|
| `ERR_MISSING_AUTHORIZATION` | 缺少 Authorization | 401 |
| `ERR_INVALID_AUTHORIZATION_FORMAT` | Authorization 格式非法 | 400 |
| `ERR_AK_NOT_FOUND` | AK 不存在 | 403 |
| `ERR_AK_DISABLED` | AK 已禁用 | 403 |
| `ERR_MISSING_DATE` | 缺少 Date | 400 |
| `ERR_DATE_OUT_OF_RANGE` | 请求时间超出窗口 | 403 |
| `ERR_SIGNATURE_MISMATCH` | 签名不匹配 | 403 |
| `ERR_NONCE_REQUIRED` | 开启 nonce 后缺少 nonce | 400 |
| `ERR_NONCE_REPLAYED` | nonce 重放 | 403 |
| `ERR_IP_NOT_ALLOWED` | IP 不在白名单 | 403 |
| `ERR_NOT_AUTHORIZED` | 权限钩子拒绝 | 403 |
| `ERR_INTERNAL` | 内部错误 | 500 |

## 9. 示例

## 9.1 GET 示例（无 body）

请求：

```text
GET /api/v1/items?page=1&size=20
Accept: application/json
Date: Mon, 16 Mar 2026 10:30:00 GMT
Authorization: acs test-ak:<signature>
```

`StringToSign`：

```text
GET
application/json


Mon, 16 Mar 2026 10:30:00 GMT
/api/v1/items?page=1&size=20
```

## 9.2 POST 示例（有 body）

请求：

```text
POST /api/v1/items
Accept: application/json
Content-Type: application/json
Content-MD5: nDqR0QJ6f0M4f6A4j0n6sw==
Date: Mon, 16 Mar 2026 10:30:00 GMT
Authorization: acs test-ak:<signature>

{"name":"demo"}
```

`StringToSign`：

```text
POST
application/json
nDqR0QJ6f0M4f6A4j0n6sw==
application/json
Mon, 16 Mar 2026 10:30:00 GMT
/api/v1/items
```

## 10. 安全建议

- `SK` 必须安全存储（KMS/密文存储），禁止明文日志输出
- 生产环境建议强制开启 HTTPS
- 建议在高风险接口启用 Nonce 防重放
- 建议配合上游限流与审计日志

## 11. 版本与兼容性

- 本文档为 `Draft`，对应 `v0.x` 迭代阶段
- 达到 `v1.0.0` 前，可能会对细节字段进行兼容性调整
