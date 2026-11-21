---
type: index
status: Accepted
updated: 2026-11-21
---

# StuHelper Open Platform

开放平台负责第三方应用审批、逐项用户授权、业务令牌、调用配额和撤回通知。模块在 PostgreSQL 的 `open_platform` schema 中保存应用、授权、通知、幂等回执及审计。业务数据通过所属模块的公开接口实时读取。源码使用 AGPL-3.0-only。

## 依赖与公开接口

[模块清单](module.yaml) 声明 platform、identity 和 profiles 为必需依赖，提供 `open-platform.manage` 和 `open-platform.data` 两项能力。账号认证来自 identity，当前账号状态由 backend 装配的账号事实接口检查。

| 信息范围 | 提供方与行为 |
| --- | --- |
| `student_status`、`schools` | verification 提供当前学生资格与学校。 |
| `qq_binding_status`、`qq_binding_details` | qq-binding 提供可信绑定事实。两档独立审批和授权。同意页的 `qq_tiers` 展示具体档位。三项身份全部验证后，详情档可返回 OneBot QQ 号码。 |
| `profile` | profiles 提供昵称与简介。`profile.id` 与 `subject` 相同，按应用隔离。 |
| `schedule` | catalog 提供本人有效选课及已知排课。空 `meetings` 表示来源未提供排课信息。 |
| `catalog`、`public_reviews` | catalog、reviews 提供当前可读内容，查询仍须满足提供方的内容准入。OpenAPI 允许公开评价携带关联修读学期的 `term_id`。 |

verification、catalog、reviews 和 qq-binding 为可选依赖。对应信息来源缺失或故障时，该范围的读取返回 503。QQ 来源明确报告绑定未完成时，仅投影未绑定状态。

HTTP 接口见 [OpenAPI](contracts/open-platform.openapi.json)。生成的 Go 与 TypeScript SDK 位于 [sdk](sdk)，服务端接口与路由定义位于 [httpapi](httpapi)。业务规则见 [第三方开放平台规格](https://github.com/StuHelper/stuhelper/blob/develop/docs/spec/open-platform.md)。

## 应用审批与逐项授权

开发者提交名称、用途、HTTPS 回调和申请范围，每账号最多 100 个应用。管理员可按应用状态及申请人筛选，按更新时间倒序查看申请与有效授权规模，并设置批准范围、授权期限、令牌期限和 UTC 日配额。

用户使用 StuHelper 会话创建授权请求。服务端返回应用摘要、申请范围和已生效的授权范围，绑定请求人、应用修订、精确登记的回调、范围、`state` 和 PKCE S256。请求有效 5 分钟，每账号同时最多 100 个未过期、未决定的授权请求。

逐项同意时可选合并已有授权（`merge`）或覆盖（`replace`）。授权码只能成功交换一次，有效 60 秒。公开应用和机密应用均须提供 PKCE 证明，机密应用还须使用 HTTP Basic 应用凭据。

访问令牌最长 1 小时，并受授权到期时间限制。令牌到期或交换结果不明时重新发起授权。管理和同意接口使用用户会话，业务读取使用应用获得的访问令牌。

每次凭据轮换只在首次成功响应中返回明文，相同幂等键重试返回 `retrievable=false`。丢失响应后读取凭据修订，再发起轮换。数据库保存凭据与授权码的哈希，幂等回执省略授权码。授权码派生使用由私有配置管理的 32 字节随机密钥。

服务端验证应用、回调和 PKCE 证明后，才会因重放而撤销该授权码签发的令牌。对未绑定授权码标识的旧令牌，撤销范围为同一授权。

## 数据读取与终止处理

服务端在提供方调用前后检查应用和授权修订、到期时间及封存状态。应用日配额在初次校验时原子扣减，获准调用后的提供方失败也计入。应用详情返回当日用量，业务响应头返回上限和余量。429 响应通过 `Retry-After` 返回到下一 UTC 零点的秒数。

列表每页最多 100 条。业务数据实时读取。提供方调用限时 3 秒，数据库操作限时 5 秒。错误响应使用稳定的 `code` 及细分 `reason`。最近数据读取时间最多每分钟更新一次，业务写入、必要审计与幂等回执同事务提交。

已授权应用按有效状态优先、更新时间倒序分页，可按状态筛选并查看终止原因。用户可撤回部分范围或整单授权。撤回、停用或审批修订变化使相应旧令牌立即失效；恢复接入需要用户重新授权。

账号注销在同一事务封存账号并停用名下应用。主动归档的应用进入停用状态并留出通知处理期。停用或归档后，应用凭据仅用于读取通知和提交回执。

`Work` 为到期、停用及注销的授权生成终止通知，每轮最多 100 条、10 秒。应用可用凭据或开发者会话按顺序游标分页读取通知，可用 `pending_ack` 筛选，管理员可巡检逾期待回执的应用。

第三方回执可沿 `received`、`retention_exception`、`deleted` 的顺序推进。法定保留例外必须填写理由。`seen_at` 记录读取时间，`deleted` 记录第三方报告的删除结果。

## 清理与审计

`Cleanup` 在同一事务内按八类分别清理，每类最多 100 条、整轮最多 800 条，最长 5 秒。幂等回执保留 24 小时，授权请求过期后保留 24 小时，令牌到期即符合清理条件。日配额保留当天和前一 UTC 日期。

审计和通知在创建满 12 个月后可清理。主动归档满 12 个月后，依照令牌、授权、通知等关联记录的清理顺序删除应用，释放应用数量配额。`Backlog` 返回应发通知与各类应清理记录的最早到期时间和滞后秒数。

平台审计由 backend 通过 `postgres.Repository.ReadAudit` 查询。调用方先认证并与当前授权求交，仓储再按照范围和全部查询条件过滤。审计身份只读 `events` 和 `audit_retention`，与模块运行及迁移身份分开。

审计按时间、模块与 ID 字节序倒序，每批最多 101 条，查询时间窗口左闭右开。分页使用全局位置与 PostgreSQL 可见性快照，排除回填和延迟提交。更新或删除审计记录使旧快照失效。

审计摘要包含必要的内部对象与操作者标识、动作、时间、范围、原因和结果。范围未知时只对全局权限可见。原因超过 512 字节或包含控制字符时省略，结果无法确定时返回 `unknown`。

## 运行与检查

迁移身份通过 `postgres.Migrate` 建立和升级表结构。业务与清理身份的表权限限于本 schema。`requests`、`events` 和 `tokens` 允许 SELECT、INSERT 与 DELETE，序列只授予 USAGE。

准备本地工具与隔离 PostgreSQL，执行以下命令。可用 `STUHELPER_TEST_PG_BIN` 指定 PostgreSQL 二进制目录。

```sh
make setup
bash scripts/check-with-postgres.sh
```

脚本启动只接受本机 Unix socket 的临时数据库，设置 `STUHELPER_OPEN_PLATFORM_TEST_DSN` 并执行 `make check`。已有隔离测试库时，可直接设置该环境变量后执行 `make check`。接口变更使用 `make generate` 更新生成结果。

[模块清单](module.yaml) 的 `scenario_tests` 将审批、逐项授权、撤回、审计与清理场景映射到测试函数。检查范围与交付状态见 [开放平台文档](docs/README.md)。
