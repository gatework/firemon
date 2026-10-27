# Changelog

## Unreleased — Go implementation in progress

- Replace the Ruby gem skeleton with a Go module and offline CLI.
- Add the immutable firewall graph, separate StaticNAT and DynamicNAT catalogs, staged configuration parsing, exact policy and NAT evaluation, snapshot persistence, change proofs, deployment orchestration and lifecycle analysis.
- Add initial Hillstone, Palo Alto and ASA implementations with synthetic tests. See [implementation status](docs/status.md) for supported behavior and remaining work; this is not a release or full vendor parity.

## 0.1.0 - 2026-10-17

- 初始化 gem 命名空间、版本常量和基础异常。
- 集成 Ruby 3.3、3.4、4.0 CI、gem 隔离安装验证和 GitHub Release 自动发布。
- 当前版本为项目骨架，尚未实现设备连接或命令操作。
