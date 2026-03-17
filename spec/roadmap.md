# ak-auth-go Roadmap

## 1. 产品定位与边界

`ak-auth-go` 是一个可复用的 AK 鉴权内核库，目标是为上游服务提供统一的签名/验签能力。

### 做什么

- 提供与业务无关的签名与验签内核
- 提供可插拔策略接口（按需启用）
- 提供 Web 框架适配层

### 不做什么

- 不定义 AK 表结构
- 不管理 AK 生命周期（创建、轮换、禁用）
- 不内置具体 RBAC/ACL 模型

## 2. 里程碑规划

## M0: 协议与接口冻结（文档阶段）

- 明确签名字符串构造规则（method/path/query/headers/body）
- 明确头部约定（Authorization/Date/可选 Nonce）
- 明确错误码与错误类型
- 冻结核心接口：`SecretProvider`、`Verifier`、`Signer`、`SignatureAlgorithm`

交付物：

- `spec/ak-signature.md`（协议细则）
- `spec/roadmap.md`（本文件）

## M1: v1 核心能力（必须）

- 支持 `GET/POST/PUT/PATCH/DELETE` 的签名/验签
- 规范化请求构建（包含 query 排序与编码约定）
- 签名算法接口化，并支持 `HMAC-SHA256`、`HMAC-SHA1`、`HMAC-SHA512` 切换（默认 `HMAC-SHA256`）
- 时间窗口校验（默认开启）
- 统一验证结果与错误类型
- Fiber 中间件适配

验收标准：

- 核心单测覆盖：签名一致性、边界请求、时间窗口
- 三种 HMAC 算法切换均有通过用例
- Fiber 示例可运行并完成验签通过/失败验证

## M2: v1 可选扩展（Options）

- `WithNonceStore(...)`：启用 Nonce 防重放
- `WithIPPolicy(...)`：启用 IP 白名单策略
- `WithAuthorizer(...)`：启用权限钩子（allow/deny）

验收标准：

- 未启用 options 时不影响主流程
- 各扩展有独立单测，且可与主流程组合使用

## M3: 框架扩展与生态

- 新增 `server/gin` 适配
- 新增 `server/echo` 适配（可选）
- 完善 `examples/`（客户端签名示例 + 服务端验签示例）

## M4: 稳定化与发布

- 补全安全测试（重放、伪造、异常输入）
- 完善性能基准与压测
- 输出版本发布说明与迁移说明
- 从 `v0.x` 进入 `v1.0.0`

## 3. 扩展点清单（避免遗忘）

以下需求不在 v1 必做范围，但保留接口和计划：

- 更多签名算法（非 HMAC 家族）的可插拔实现
- Header 规范化策略可定制
- 请求体摘要策略可定制（兼容流式 body）
- 多租户/多凭据来源的 `SecretProvider` 组合器
- 调用审计事件回调（不含具体存储实现）
- 本地缓存与失效策略（提升高并发性能）

## 4. 设计约束

- 核心层不得依赖具体 Web 框架
- 扩展策略全部通过接口与 options 注入
- 默认配置仅启用：签名校验 + 时间窗口校验
- 默认签名算法为 `HMAC-SHA256`，并允许切换到 `HMAC-SHA1` / `HMAC-SHA512`
- 其它策略默认关闭，避免引入隐式行为
