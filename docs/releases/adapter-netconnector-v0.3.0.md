# Firemon connector adapter v0.3.0

- 更新为正式 `net-connector v0.9.0` 与 `go-expect v0.6.0`，Firemon 核心继续固定为 `v0.2.1`。
- **Go API 变更**：`Profile(vendor)` 改为 `Driver(vendor)`，返回 `connector.Driver`；自定义提示符和命令时使用 `connector.WithTerminal(driver, grammar)`，保留原生采集与保存校验行为。
- 保留七种规范厂商名称、配置会话隔离、回执持久化及不重放写入的恢复语义。

模块为 `github.com/gatework/firemon/adapter/netconnector`，标签为 `adapter/netconnector/v0.3.0`。本次发布只更新可选适配模块，不发布 Firemon 核心的新版本。验证使用模拟会话，不代表真实设备验收。
