# 项目拆解：Claude Code Security Reviewer（GitHub Action）系统架构与运行流程

> 注：以下文档由ChatGPT 5.2 Thinking生成。
> 目标：在 Pull Request 场景下，自动拉取 PR 上下文与 diff，调用 Claude Code（CLI）进行安全审计，再进行（可选）误报过滤与结果打包，最后上传产物并（可选）评论 PR。

---

## 1. 总体架构（组件视图）

### 1) GitHub Action（Composite Action：`action.yml`）
- **职责**：编排运行环境与执行步骤
- **关键输入**
  - `claude-api-key`（必填）
  - `claude-model`（可选）
  - `exclude-directories`（可选：目录排除）
  - `false-positive-filtering-instructions`（可选：过滤指令文件）
  - `custom-security-scan-instructions`（可选：扫描指令文件）
  - `security-policy-file`（可选：JSON 策略文件）
  - `claudecode-timeout`（可选）
  - `run-every-commit`（可选：是否跳过缓存检查）
  - `comment-pr`（可选：是否评论 PR）
  - `upload-results`（可选：是否上传 artifacts）
- **关键外部依赖**
  - GitHub API（REST）
  - GitHub Cache / Artifacts
  - GitHub CLI（`gh`，用于评论）
  - Claude Code CLI（`claude`）
  - Anthropic API（用于“误报过滤”阶段的直接 API 调用，条件开启）

### 2) Python 审计程序（入口：`claudecode/github_action_audit.py`）
- **职责**：业务主流程入口：拉取 PR 信息、构建 prompt、调用 Claude Code 扫描、过滤 findings、统一输出 schema
- **核心类 / 模块**
  - `GitHubActionClient`
    - `get_pr_data(repo, pr)`：取 PR metadata + 文件列表（并按 `exclude-directories` 过滤）
    - `get_pr_diff(repo, pr)`：取完整 unified diff（并过滤生成文件 + 排除目录）
  - `SimpleClaudeRunner`
    - `run_security_audit(repo_dir, prompt)`：通过 subprocess 调用 `claude --output-format json ...`，从输出中解析 findings
    - `validate_claude_available()`：检查 CLI 可用与 API key
  - `SecurityAuditPipeline`（`claudecode/audit_pipeline.py`）：将上述步骤串起来，带重试（prompt too long 时去掉 diff）
  - `FindingsFilter`（`claudecode/findings_filter.py`）
    - 硬规则过滤（hard exclusions）
    - 可选：调用 Anthropic API 做二次过滤（`ENABLE_CLAUDE_FILTERING=true` 且有 API key）
  - `prompts.get_security_audit_prompt(...)`：生成安全审计 prompt（可追加自定义扫描指令）
  - `audit_schema.build_audit_output(...)`：对输出进行规范化（含元数据、指标、排除原因等）
  - `security_policy.load_security_policy(...)`：加载/校验版本化策略（scan/filter 指令等）

### 3) Node 评论脚本（`scripts/comment-pr-findings.js`）
- **职责**：读取 `findings.json` / `claudecode-results.json`，用 `gh api` 给 PR 发表评论（可由输入开关控制）

---

## 2. 运行时关键数据对象（数据面）

### A) PR 上下文（来自 GitHub API）
- `pr_data`：标题、描述、作者、head/base、文件列表（含 patch 摘要等，且已排除指定目录）
- `pr_diff`：完整 unified diff（已过滤生成文件与排除目录）

### B) Prompt（送入 Claude Code CLI）
- 由 `get_security_audit_prompt(pr_data, pr_diff, ...)` 构建
- 支持：
  - include diff（默认 true）
  - custom scan instructions（来自 policy 或用户输入文件）

### C) Scan 输出（Claude Code CLI 返回 JSON wrapper）
- CLI 输出是一个 JSON wrapper，其中 `result` 字段里再包含审计 JSON（含 `findings`）
- 解析：`json_parser.parse_json_with_fallbacks`（多策略容错解析）

### D) Findings（统一结构）
- `original_findings`：扫描原始 findings
- `kept_findings`：过滤后保留
- `excluded_findings`：过滤/排除的 findings（含目录排除）

### E) 统一输出（最终 stdout & artifacts）
- `claudecode-results.json`（stdout 同内容）
- `findings.json`（便于评论脚本读取）
- `claudecode-error.log`（如有）

---

## 3. 系统运行流程（时序 + 关键决策点）

下面以 **pull_request 事件** 为主（非 PR 会直接跳过扫描）。

### 3.1 Action 编排流程（`action.yml`）
1. 安装 `gh` CLI
2. `setup-python`
3. **PR 场景缓存检查**（`actions/cache`）
   - 缓存键：`claudecode-<repo_id>-pr-<pr_number>-<sha>`
4. 决定是否启用 ClaudeCode
   - 默认启用
   - 若发现 `.claudecode-marker/marker.json` 且 `run-every-commit != true` → **禁用**（避免重复分析导致误报/噪声）
5. PR 场景下创建 reservation marker 并 save cache（避免并发重复跑）
6. `setup-node`
7. 安装依赖
   - `pip install -r claudecode/requirements.txt`
   - `npm install -g @anthropic-ai/claude-code`
   - `apt-get install jq`
8. 运行扫描（Python）
   - `python -u claudecode/github_action_audit.py > claudecode/claudecode-results.json 2> claudecode/claudecode-error.log`
   - 用 `jq` 统计 findings 数量，并生成 `findings.json`
9. 上传 artifacts（无论成功与否，尽量上传）
10. 可选：评论 PR（Node 脚本）

---

## 4. Python 主流程（`github_action_audit.py` + `audit_pipeline.py`）详细分解

### 4.1 初始化阶段
- 读取环境变量：
  - `GITHUB_REPOSITORY`、`PR_NUMBER`（必需）
  - `GITHUB_TOKEN`（必需，用于 GitHub API）
  - `ANTHROPIC_API_KEY`（必需，供 Claude Code CLI）
  - `EXCLUDE_DIRECTORIES`（可选）
  - `FALSE_POSITIVE_FILTERING_INSTRUCTIONS`（可选文件路径）
  - `CUSTOM_SECURITY_SCAN_INSTRUCTIONS`（可选文件路径）
  - `SECURITY_POLICY_FILE`（可选文件路径）
  - `CLAUDE_MODEL`（可选）
  - `CLAUDECODE_TIMEOUT`（可选）
  - `ENABLE_CLAUDE_FILTERING`（可选：是否启用 API 过滤）

- 加载策略（policy）
  - 若 `SECURITY_POLICY_FILE` 存在：`load_security_policy(file)` 校验并加载
  - 合并 custom scan instructions / filtering instructions 到 policy（用于 prompt & filter）

- 初始化客户端：
  - `GitHubActionClient()`：准备 headers，解析排除目录列表
  - `SimpleClaudeRunner()`：超时配置
  - `FindingsFilter(...)`：
    - 若 `ENABLE_CLAUDE_FILTERING=true` 且 `ANTHROPIC_API_KEY` 有值：启用 Claude API 过滤
    - 否则仅硬规则过滤

- 校验 Claude Code CLI 可用：`validate_claude_available()`

---

### 4.2 核心管线：`SecurityAuditPipeline.run(repo, pr, repo_dir)`
**Stage 1：collect_pr_context**
1. `github_client.get_pr_data(repo, pr)`
   - 调 GitHub REST：`/pulls/{pr}` 与 `/pulls/{pr}/files`
   - 文件级排除：`_is_excluded(path)`（基于 `EXCLUDE_DIRECTORIES`）
2. `github_client.get_pr_diff(repo, pr)`
   - 调 GitHub REST：`/pulls/{pr}` 但 Accept=diff（返回 unified diff）
   - diff 级过滤：跳过生成文件、跳过排除目录文件

**Stage 2：build_prompt**
3. `prompt_builder(pr_data, pr_diff, custom_scan_instructions=policy.scan_instructions)`
   - 默认 include diff
   - append 自定义扫描指令（policy）

**Stage 3：run_scan**
4. `claude_runner.run_security_audit(repo_dir, prompt)`
   - subprocess：`claude --output-format json --model <DEFAULT_CLAUDE_MODEL> ...`
   - stdin 输入 prompt（避免“参数过长”）
   - 解析：
     - 先 parse 外层 JSON wrapper
     - 再从 wrapper.result 中解析内部 JSON，提取 `findings`

5. **关键分支：PROMPT_TOO_LONG**
   - 若 Claude 输出识别为 “Prompt is too long”
   - 则 **重建 prompt（include_diff=false）并重试扫描**
   - metrics 记录：`prompt_used_diff=false`

**Stage 4：filter_findings**
6. 取 `original_findings = scan_results.findings`
7. 构建 `pr_context`（repo/pr/title/description）
8. `apply_findings_filter_with_exclusions(...)`
   - `findings_filter.filter_findings(original_findings, pr_context)`
     - 先硬规则过滤（如路径/模式/重复等）
     - 可选 Claude API 再过滤（将“误报”标出并给出 reason）
   - **最终强制目录排除**：对“保留列表”再跑一遍 `github_client._is_excluded(file)`
   - 输出：`final_kept_findings`, `all_excluded_findings`, `filter_analysis_summary`

**Stage 5：package_output**
9. `build_audit_output(...)`
   - 输出标准 schema（含 policy/version/source）
   - 汇总：保留 findings、排除 findings、过滤分析、原始 findings 数、pipeline metrics（各阶段耗时、是否用 diff 等）
10. 计算 high severity 数（用于 Action exit code 决策）

---

## 5. 端到端时序图（ASCII）

```text
GitHub PR Event
   |
   v
[Composite Action action.yml]
   |-- install gh / setup python / setup node
   |-- cache check + marker reservation (PR only)
   |-- pip install + npm install -g @anthropic-ai/claude-code + install jq
   |
   v
[python claudecode/github_action_audit.py]
   |-- load policy (optional) + read custom instructions (optional)
   |-- init GitHubActionClient (needs GITHUB_TOKEN)
   |-- init SimpleClaudeRunner (calls `claude` CLI)
   |-- init FindingsFilter (optional Claude API)
   |-- validate Claude CLI available
   |
   v
[SecurityAuditPipeline.run]
   |-- (1) GitHub API: get_pr_data + get_pr_diff (apply exclusions + generated filter)
   |-- (2) build prompt (include diff by default)
   |-- (3) run `claude` CLI (stdin prompt) -> parse JSON -> findings
   |       \-- if PROMPT_TOO_LONG -> rebuild prompt w/o diff -> rerun
   |-- (4) filter findings (hard rules, optional Claude API)
   |       \-- enforce directory exclusions again (final gate)
   |-- (5) build_audit_output (normalized schema + metrics)
   |
   v
stdout -> claudecode/claudecode-results.json
   |
   v
[action.yml]
   |-- jq count findings -> findings.json
   |-- upload artifacts (findings.json, claudecode-results.json, error.log)
   |-- (optional) node scripts/comment-pr-findings.js -> gh api -> PR comment
   |
   v
Done