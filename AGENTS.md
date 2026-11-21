---
type: guide
status: Accepted
updated: 2026-11-21
---

# 工程约定

更新日期：2026-11-21。

遵循 [主工作区工程约定](https://github.com/StuHelper/stuhelper/blob/develop/AGENTS.md)。本模块维护应用、授权、令牌、配额、撤回通知与审计。backend 通过所属模块的公开接口提供业务事实，PostgreSQL 查询留在 `postgres/`。

修改 HTTP 接口时先维护 [OpenAPI](contracts/open-platform.openapi.json)，再运行 `make generate`。将已实现的业务场景和实际测试函数登记到 [模块清单](module.yaml) 的 `scenario_tests`。

使用隔离 PostgreSQL 与独立运行身份验证并发、迁移和权限。平台审计查询使用专用只读身份。开发和 CI 使用合成账号、令牌及业务数据。
