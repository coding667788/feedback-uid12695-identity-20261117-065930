# JSON 解析差异下的签名边界审计工具

离线分析工具：模拟**网关**与**业务服务**对同一 JSON 报文的解释差异，识别由此产生的授权风险，并给出安全规范化表示与签名边界验证。

- 环境：Windows、Python 3.12、仅 CPU、仅标准库（未使用 cryptography，签名用 `hmac`/`hashlib` 模拟）。
- 不使用 Docker、不访问任何外部服务；所有输入样例由 `tools/make_samples.py` 在项目内确定性生成。

## 快速开始

```bash
# 在项目根目录（本 README 所在目录）执行
python -m solution --input cases.json --output result.json
python -m unittest discover -s tests -v
```

重新生成样例（可选，输出逐字节确定）：

```bash
python tools/make_samples.py
```

## 威胁模型

网关校验签名后把**原始报文字节**转发给业务服务。若两侧解析器在以下两轴上选择不同，同一份字节会被解释成两份不同的授权数据：

| 轴 | 网关策略（模拟） | 业务服务策略（模拟） |
|---|---|---|
| 重复对象键 | `first-key`（取首次出现） | `last-key`（取末次出现） |
| 数值解释 | `exact-integer`（`Decimal` 精确十进制） | `ieee754`（binary64 浮点） |

典型攻击：`{"role":"user","role":"admin"}` —— 网关按 first-key 看到 `user` 并放行，服务按 last-key 看到 `admin`。`9007199254740993`（2^53+1）在 IEEE754 下被静默舍入为 `9007199254740992.0`，金额被改写。

## 架构

```
solution/
  parser.py     字节级递归下降解析器 -> 信息保留解析树
  nodes.py      树节点：JObject 保留全部重复键与顺序；JNumber 保留原始文本
  policy.py     4 种解释策略 + 受保护路径读取（PathEvidence 含原始文本/重复次数）
  diff.py       网关/服务双视图语义差异分类
  canonical.py  安全规范化表示（验证 + 输出）
  signature.py  HMAC-SHA256 签名模拟；签名/验证/业务读取共用同一已验证树
  audit.py      单用例分析流水线：parse -> diff -> canonical -> sign/verify
  __main__.py   CLI 入口
tests/          78 个断言式单元测试
samples/        输入样例（含二进制坏样例），由 tools/make_samples.py 生成
cases.json      用例清单（file/inline 两种来源）
```

### 1. 信息保留解析树（要求 1）

- 直接解析 `bytes`，**不先整体解码**，因此所有错误偏移都是**字节偏移**（流式输入下同样成立）。
- `JObject.pairs` 是有序列表，重复键全部保留；`JNumber.raw` 保留原始数值文本（`1e2` 与 `100` 可区分），解析阶段不做任何浮点转换。
- 字符串支持全部 JSON 转义，`\uXXXX` 代理对正确合并；孤立代理（`E_UNICODE`）、非法/截断/过长 UTF-8（`E_UTF8`）、未转义控制字符、前导零等均拒绝（`E_SYNTAX`）。
- 嵌套深度上限默认 128（`--max-depth` 可调），超限报 `E_DEPTH`。

### 2. 语义差异（要求 2）

对受保护路径 `tenant`、`amount`、`role`（可在 cases.json 中覆盖，支持 `a.b` 点路径），分别在网关/服务两种策略组合下取值并分类：

| 分类 | 含义 | 危险 |
|---|---|---|
| `equal` | 值与来源完全一致 | 否 |
| `absent` | 两侧都缺失 | 否 |
| `serialization_only` | 语义值相同，仅序列化有歧义（原始数值文本不同，或取值来自重复键） | 否（仍留证据） |
| `value_diff` | 授权数据值不同 | **是** |
| `type_diff` | JSON 类型不同（如字符串 vs 对象） | **是** |
| `presence_diff` | 一侧缺失 | **是** |

### 3. 安全规范化与签名边界（要求 3）

规范化规则（固定，不放宽）：

- UTF-8 编码、无多余空白；对象键按 **Unicode 码点**排序；数组顺序保留。
- **所有层**的重复键一律拒绝（`E_DUP_KEY`）；键在转义解码后比较，`tenant` 与 `tenant` 判为冲突。
- 数值仅接受整数语法（无小数点/指数），且 `|v| <= 2^53 - 1`（`E_NON_INTEGER` / `E_RANGE`）；`-0` 统一输出为 `0`。
- 字符串最小化转义，非 ASCII 直接输出 UTF-8（不用 `\uXXXX`），保证**幂等**：`canonicalize(parse(canonicalize(tree))) == canonicalize(tree)`（有测试断言）。

签名边界不变式：`sign_tree` / `verify_tree` / `read_verified` 作用于**同一棵已验证解析树**；业务读取不得在验证后重新解析原始字节。由于重复键被整体拒绝，危险报文**无法通过重排键逃逸**（测试对全部键序排列断言 `E_DUP_KEY`）。

签名密钥由固定种子 `uid12695-json-sig-boundary-audit-fixed-seed-v1` 经 SHA-256 派生，输出无任何时间戳/随机源 —— 同一输入重放产生**逐字节相同**的 result.json（有测试断言）。

## 输入 schema（cases.json，version 1）

```json
{
  "version": 1,
  "protected_paths": ["tenant", "amount", "role"],   // 可选，默认此三条
  "max_depth": 128,                                   // 可选
  "cases": [
    {"name": "valid-basic", "file": "samples/valid-basic.json"},
    {"name": "inline-demo", "inline": "{\"tenant\":\"acme\",\"amount\":42,\"role\":\"user\"}"}
  ]
}
```

- `file`：相对 cases.json 所在目录解析，**始终按原始字节读取**（因此可引用 `.bin` 二进制坏样例）。
- `inline`：JSON 字符串，按 UTF-8 编码后分析。
- 两者必须且只能出现一个，否则该用例记 `E_SCHEMA`。

## 输出 schema（result.json）

```json
{
  "tool": "json-sig-boundary-audit",
  "schema_version": 1,
  "seed": "uid12695-json-sig-boundary-audit-fixed-seed-v1",
  "policies": {"gateway": {...}, "service": {...}},
  "protected_paths": [...],
  "max_depth": 128,
  "canonical_rules": {...},
  "cases": [ <case>, ... ],
  "summary": {"total": N, "pass": N, "risky": N, "rejected": N, "errors": N}
}
```

每个 `<case>`：

| 字段 | 说明 |
|---|---|
| `name` / `source` | 用例名 / 来源（`{"type":"file","path":...}` 或 `{"type":"inline"}`） |
| `parse` | `{"ok":true}` 或 `{"ok":false,"error":{"code","message","offset"}}`，offset 为字节偏移 |
| `diffs` | 每条受保护路径：`classification`、`dangerous`、两侧 `PathEvidence`（`present/kind/value/raw/occurrences/offset`；数值一律以字符串输出，不丢精度） |
| `authorization_risk` / `risk_reasons` | 是否存在危险差异及原因 |
| `canonical` | `{"ok":true,"utf8","sha256"}` 或 `{"ok":false,"error":{...}}` |
| `signature` | `{"algorithm":"HMAC-SHA256","canonical_sha256","signature","verified"}`；规范化失败时为 `null` |
| `verified_read` | 签名验证后从**同一棵树**读出的受保护字段证据 |
| `verdict` | `pass` / `risky` / `rejected-by-canonicalization` / `rejected-unparseable` / `error` |

CLI 退出码：分析完成 `0`；cases.json 本身无法读取/解析 `2`。

## 错误码

| 代码 | 阶段 | 含义 |
|---|---|---|
| `E_UTF8` | 解析 | 非法/截断/过长 UTF-8 序列 |
| `E_SYNTAX` | 解析 | JSON 语法错误（含未转义控制字符、尾随数据、前导零等） |
| `E_UNICODE` | 解析 | 非法 `\uXXXX` 转义、孤立代理项 |
| `E_DEPTH` | 解析 | 嵌套超过 max_depth |
| `E_DUP_KEY` | 规范化 | 任一层出现重复键（转义解码后判定） |
| `E_NON_INTEGER` | 规范化 | 数值非整数语法（含 `1.5`、`1e2`、`-0.0`） |
| `E_RANGE` | 规范化 | 整数绝对值超过 2^53-1 |
| `E_SCHEMA` | 用例装载 | 用例定义非法 |
| `E_IO` | 用例装载 | 用例文件不可读 |

## 验收场景覆盖

| 场景 | 样例 | 预期 |
|---|---|---|
| 重复键嵌套 | `dup-tenant-nested.json` | 嵌套重复键被规范化拒绝（`E_DUP_KEY`） |
| 转义后同名键 | `escaped-duplicate-key.json` | 解码后与 `tenant` 冲突：diff `value_diff` + `E_DUP_KEY` |
| 2^53 附近金额 | `amount-2p53-plus1.json` / `valid-safe-max.json` | 2^53+1：网关 `9007199254740993` vs 服务 `9007199254740992.0`（`value_diff`+`E_RANGE`）；2^53-1 两视图一致且通过 |
| 负零 | `negative-zero.json` | 规范化为 `0`，两视图一致 |
| 代理对 | `surrogate-pair.json` / `lone-surrogate.json` | 合法代理对正确解码并以 UTF-8 输出；孤立代理 `E_UNICODE` |
| 规范化幂等 | 测试 `test_idempotent_on_valid_documents` | 二次规范化字节不变 |
| 重排键不可逃逸 | 测试 `test_dangerous_doc_cannot_escape_by_reordering_keys` | 危险报文所有键序排列均 `E_DUP_KEY`，无法被签名 |
| 仅序列化不同 | `serialization-only-dup.json` | `1e2` vs `100` 判 `serialization_only`，不计授权风险但仍被规范化拒绝 |

## 可重放性

- 签名密钥来自固定种子；报告不含时间戳与随机数据。
- `test_fixed_seed_replay_is_byte_identical` 断言两次运行输出逐字节相同。
- `python tools/make_samples.py` 重新生成的样例逐字节确定。

## 非安全性细节的设计决定（题面未指明部分）

- 受保护路径默认为顶层 `tenant`/`amount`/`role`，支持点分隔嵌套路径，可在 cases.json 覆盖。
- `exact-integer` 策略用 `Decimal` 表示任意精确十进制（含 `1e2` 这类非整数语法），是否允许进入签名域由规范化阶段单独把关（一律拒绝非整数语法）。
- 解析失败/规范化失败的报文不计入 `authorization_risk`（风险发生在“两侧都接受但解释不同”时），而是以 `rejected-*` verdict 单独报告。
- 嵌套深度上限默认 128，可用 `--max-depth` 或 cases.json 的 `max_depth` 调整。
