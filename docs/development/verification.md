---
type: development
status: Accepted
updated: 2026-11-21
---

# 开放平台验证记录

## 已实现

开放平台模块提供应用审批、逐项授权、PKCE 令牌交换、业务数据投影、撤回通知、审计查询和到期清理。backend 负责业务事实适配、挂载 HTTP 接口和启动后台处理。

## 已验证

develop 的独立模块检查通过。检查包含仓库和 SQL 边界、文档、生成一致性、竞态检查及隔离 PostgreSQL 测试。[Open platform checks](https://github.com/StuHelper/stuhelper-open-platform/actions/runs/44606477623)

`module.yaml` 登记 OP-01 至 OP-11、AUDIT-01 和 RET-05。已登记的测试覆盖审批与范围交集、授权码重放、撤回时的在途读取、QQ 双档、审计快照和有界清理。

StuHelper v0.1.31 的正式源码组合固定开放平台 v0.1.1。实际运行状态由运维发布记录维护。[StuHelper 发行组合](https://github.com/StuHelper/stuhelper/releases/download/v0.1.31/COMPONENTS.json)

## 待验证

实际账号与第三方应用的审批、同意、数据读取、撤回和通知回执待联调。模块的公开评价投影支持可选 `term_id`，宿主从评价记录透传该字段的端到端结果待验证。
