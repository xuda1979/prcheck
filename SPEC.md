# 04 — GitHub PR-Check: PR 安全 Checklist + OpenAPI changelog

## 定位
GitHub / Copilot 生态切片：为 GitHub 仓库自动生成 PR「代码审查 checklist + 安全核对单」，
并对 OpenAPI 变更生成可读 changelog。母市场：GitHub 运行率 $2B+。
单人切：$1K–$100K MRR（可做成 GitHub App / Action / 本地 CLI）。

## 主要痛点
- 人工 PR 审查漏掉安全面（权限提升、密钥、不安全的 diff）
- API 变更（OpenAPI yaml）发布后破坏下游而没人记录
- 团队没有统一的合并前 checklist 落地工具

## 功能需求
1. 本地 / Action 两种模式采集信息：
   - 输入：`PR diff`（通过 `gh pr diff` 或本地 git diff）+ files changed 统计
   - 输入 2：OpenAPI spec（openapi.yaml）与上一版对比
2. 生成 PR Checklist：
   - 安全核对：鉴权/授权变更、密钥、依赖、注入、CORS、越权
   - 数据核对：api 变更（Breaking/Non-breaking）
   - 行为核对：log 敏感信息、异常处理
3. OpenAPI changelog：
   - 新增/移除/修改 endpoints、parameters、schemas（按 semantic version 推断 breaking）
4. 输出：Markdown 评论（PR）/ 本地报告。用 `gh` 可在 CI 发布评论
5. 门禁：`--require-high-ok` 时，未解决 high 项提示拒绝合并
6. 缓存/增量：同一 base 不重复分析

## 非目标
- 深度静态分析（交给 03 模块：本项目只做 checklist/元数据级）
- 全 GitHub App 托管平台（第 2 期）
- 多服务编排

## 技术栈
- Python 3.14（CLI）或 Node v22，两种实现均可（择一）
- OpenAPI 解析：openapi-spec-validator / swagger-parser（或 node @apidevtools）
- git/gh CLI 调用来取 diff 与发评论
- 测试：fixtures（示例 PR diff + 多个 OpenAPI 版本）

## 低算力守则
见全局。规则引擎本地，LLM 可选摘要（mock 可用）。

## AC
1. 给定一段示例 diff，输出含安全/数据/行为三类的 checklist，每项有 file:line
2. 错误的「无鉴权新路由」diff 会被 checklist 标记为 high
3. 给两个 openapi spec（v1/v2），输出 breaking 变更清单（endpoint/schema 层面）
4. SARIF/Markdown 输出都可生成；markdown 可贴 PR 评论（给出样例）
5. 选择性开关（--security only 等）
6. 测试 + fixtures + README + 示例 PR 演练（gh 模拟）

## Phases
- P0: diff → checklist 引擎（规则库）+ CLI
- P1: OpenAPI changelog（SW 版本推断）
- P2: GitHub Action + 评论发布 + 门禁
- P3: App（webhook 托管）加分

## 里程碑
M1: diff checklist + 门禁（MVP）
M2: OpenAPI changelog
M3: GitHub Action 集成

## 变现
- Action 免费，SaaS = 集中管理（规则库/审计/多仓库仪表板）
