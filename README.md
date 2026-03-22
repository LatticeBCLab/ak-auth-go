# ak-auth-go

English | [简体中文](./README.zh-CN.md)

A reusable Go library for AccessKey-based (AK/SK) request authentication.

## Current Focus

In the `v1` stage, this project focuses on a general-purpose AK authentication core:

- Provide request signing and signature verification capabilities
- Offer adapter layers for different web frameworks
- Keep future extensions pluggable through `options`

## v1 Scope

The following capabilities are required in `v1`:

- Request signing and verification for `GET/POST/PUT/PATCH/DELETE`
- Canonical request construction
- Interface-based signature algorithms with built-in support for `HMAC-SHA256`, `HMAC-SHA1`, and `HMAC-SHA512` (default: `HMAC-SHA256`)
- Time window validation for basic replay protection
- A unified error model and verification result
- A Fiber adapter layer, with more framework adapters planned later

## Optional v1 Extensions

The following capabilities are provided through `options` and interface injection, and are disabled by default:

- `Nonce` replay protection through the `NonceStore` interface, backed by Redis, a database, or other stores
- IP allowlist checks through the `IPPolicy` interface
- Authorization hooks through the `Authorizer` interface for simple allow/deny decisions

## Non-Goals

These responsibilities are intentionally left to upstream systems:

- AccessKey schema design and credential data management
- AccessKey lifecycle management such as creation, disablement, and rotation
- Business-specific RBAC or ACL modeling

## Project Layout

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
├── README.md
└── README.zh-CN.md
```

## Directory Responsibilities

- `core/`
  - Protocol-agnostic core abstractions and shared primitives
  - No dependency on any specific web framework

- `signer/`
  - Client-side signing logic
  - Builds canonical requests and generates signatures from AK/SK credentials

- `verifier/`
  - Server-side verification logic
  - Validates signatures, time windows, and optional anti-replay strategies

- `server/fiber/`
  - Fiber middleware adapter
  - Converts HTTP requests into verification input and returns unified authentication errors

- `examples/fiber-server/`
  - Runnable example for quick integration testing and local verification

- `spec/`
  - Protocol specifications and compatibility notes
  - Defines canonicalization rules, required headers, and error semantics

## Design Goal

The goal is to keep cryptography and signing rules inside `core`, `signer`, and `verifier`, while isolating framework-specific logic in `server/*` adapters. This allows multiple services to reuse the same AK authentication kernel with minimal integration cost.

## Planning Documents

- Future capabilities and milestone planning: [spec/roadmap.md](./spec/roadmap.md)
- AK signature protocol draft: [spec/ak-signature.md](./spec/ak-signature.md)

## Module Path

`github.com/LatticeBCLab/ak-auth-go`
