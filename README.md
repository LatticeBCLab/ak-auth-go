# ak-auth-go

一个可复用的 Go 语言 AccessKey（AK/SK）鉴权库。

## 当前目标

本库在 `v1` 阶段聚焦于通用 AK 鉴权内核：

- 仅负责接口签名/验签能力
- 对不同 Web 框架提供适配层
- 通过可插拔 `options` 预留扩展能力

## v1 范围（必须实现）

- 请求签名与验签（支持 `GET/POST/PUT/PATCH/DELETE`）
- 规范化请求（Canonical Request）构建
- 签名算法面向接口实现，内置 `HMAC-SHA256`、`HMAC-SHA1`、`HMAC-SHA512` 可切换（默认 `HMAC-SHA256`）
- 时间窗口校验（基础防重放）
- 统一错误模型与验证结果
- Fiber 适配层（后续逐步扩展到其它框架）

## v1 扩展能力（按需启用）

以下能力以 `options` / 接口注入的方式提供，默认关闭：

- `Nonce` 防重放（通过 `NonceStore` 接口接入 Redis/DB 等）
- IP 白名单（通过 `IPPolicy` 接口）
- 权限控制（通过 `Authorizer` 钩子，仅做 allow/deny）

## 非目标（交给上游）

- AK 表结构设计与数据管理
- AK 生命周期管理（创建、禁用、轮换）
- 业务 RBAC/ACL 模型细节

## 项目结构

```text
ak-auth-go/
├── core/
├── signer/
├── verifier/
├── server/
│   └── fiber/
├── examples/
│   └── fiber-server/
├── spec/
├── go.mod
└── README.md
```

## 目录职责

- `core/`
  - 协议无关的核心抽象与通用能力。
  - 不依赖任何 Web 框架。

- `signer/`
  - 客户端签名逻辑。
  - 负责构建规范化请求并基于 AK/SK 生成签名。

- `verifier/`
  - 服务端验签逻辑。
  - 负责校验签名、时间窗口以及可选的防重放策略。

- `server/fiber/`
  - Fiber 中间件适配层。
  - 将 HTTP 请求转换为验签输入，并输出统一的鉴权错误响应。

- `examples/fiber-server/`
  - 可运行示例，用于快速联调和接入验证。

- `spec/`
  - 协议规范与兼容说明。
  - 定义规范化规则、必选请求头和错误语义。

## 设计目标

将密码学与签名规则沉淀在 `core/signer/verifier`，将框架相关逻辑放在 `server/*` 适配层，确保不同服务可以以最小改造成本复用同一套鉴权内核。

## 规划文档

- 未来能力与阶段计划见：[spec/roadmap.md](./spec/roadmap.md)

## 模块路径

`github.com/LatticeBCLab/ak-auth-go`
