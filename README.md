# Storage Analyzer Safe

![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows-lightgrey)
![python](https://img.shields.io/badge/python-3.7%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-none%20(stdlib)-success)
![mode](https://img.shields.io/badge/default-read--only-00b42a)

> 一个面向磁盘空间排查的 **Claude Code Skill**：只读扫描 macOS / Windows 的高占用位置，把清理对象分成绿 / 黄 / 红三级，生成一份自包含的可交互 HTML 报告。**默认零破坏**，可选的本地服务也只能「移到废纸篓」或「在文件管理器里打开」，**没有任何直接删除 / `rm` 路径**。

适合在「磁盘满了」「想清缓存」「内存满了（口语里指存储）」这类场景下，先看清空间都被谁吃掉了，再决定清不清、怎么清。

---

## ✨ 特性

- **默认只读**：扫描器只读取大小 / 列表 / 元数据，永不创建、移动或删除任何东西。
- **三级分类**：🟢 可自动清（纯缓存 / 临时文件） · 🟡 需你参与（含用户数据） · 🔴 谨慎清理（应用本体 / 核心数据，建议走正规卸载）。
- **自包含报告**：一个单文件 HTML，把数据内联进去，离线可看、可分享（注意隐私，见下）。
- **Agent 驱动**：`scan.py` 只负责采集原始数据，由 Claude 解读、分级、生成分析 JSON，再渲染成报告。
- **可选服务模式**：`server.py` 起一个本地服务，让报告页面上的按钮能「移到废纸篓 / 回收站」或「在访达 / 资源管理器里打开」——可逆、有护栏、每次操作前浏览器二次确认。
- **零依赖**：纯 Python 3 标准库；macOS 复用 `du` / `diskutil` / `sw_vers` / `osascript` / `open` 等系统工具。

---

## 🔒 安全模型

这个 skill 名字里的 "safe" 是认真的，威胁模型在设计时就考虑了：

| 防线 | 说明 |
|---|---|
| **只读默认** | 不启动 `server.py` 时，全程只有扫描与静态报告，没有任何写操作。 |
| **无不可逆删除** | 服务模式只有 `open` 和 `trash` 两种操作；没有 `rm`、没有「清空废纸篓」、没有「卸载应用」。移到废纸篓 / 回收站均可恢复。 |
| **本地绑定 + 随机端口** | 服务只绑定 `127.0.0.1` 的随机端口，不监听外网。 |
| **随机会话令牌** | 每次启动生成一次性随机 token，所有写操作都必须携带；外部页面拿不到 token。 |
| **DNS Rebinding 防护** | 校验 `Host` 头必须是 `127.0.0.1` / `localhost`，挡住恶意网页通过 DNS 重绑定打本地服务。 |
| **realpath 白名单** | 每个请求路径先 `realpath` 解析（穿透符号链接），再精确匹配本次报告生成的白名单集合，并用 `commonpath` 做越界校验（不是有前缀漏洞的 `startswith`）。 |
| **受保护目录** | `trash` 只允许 `$HOME` 内的非顶层路径；`$HOME` 本身及 `Desktop` / `Documents` / `Downloads` / `Library` / `Movies` / `Music` / `Pictures` / `Public` 一律拒绝。 |
| **二次确认** | 页面上每个删除 / 打开动作都会弹确认框。 |

> ⚠️ 即便有这些护栏，最终是否安全仍取决于分析阶段把哪些路径放进了 `trash_paths`。请遵守 `SKILL.md` 里的 Safety Contract：**只把核实过的、具体的缓存 / 临时子路径放进 `trash_paths`，绝不放入 `$HOME` 或宽泛的用户数据目录。**

---

## 📦 安装

本仓库本身就是一个 Claude Code Skill（根目录即 `SKILL.md`）。安装方式就是把它放进 Claude Code 的 skills 目录——**目录名决定命令名**，所以请保持目录名为 `storage-analyzer-safe`，安装后即可用 `/storage-analyzer-safe` 触发。

**个人 skill（推荐，对你所有项目可用）：**

```bash
git clone https://github.com/BetterThanAny/storage-analyzer-safe.git \
  ~/.claude/skills/storage-analyzer-safe
```

**项目 skill（只在当前仓库可用）：**

```bash
git clone https://github.com/BetterThanAny/storage-analyzer-safe.git \
  .claude/skills/storage-analyzer-safe
```

安装后的目录结构应为 `~/.claude/skills/storage-analyzer-safe/SKILL.md`（以及 `scripts/`、`references/`、`assets/` 等同级子目录）。

**生效与验证：**

- 若 `~/.claude/skills/` 目录在本次会话启动前已存在，新增 skill 会被实时检测，无需重启；若是首次创建顶层 `skills/` 目录，则重启一次 Claude Code。
- 直接输入 `/storage-analyzer-safe`，或在对话里描述存储问题（如「我磁盘快满了，帮我看看」）让 Claude 自动触发。

> 不想作为 skill 使用？三个脚本也能独立运行，见下方「使用」。

---

## 🚀 使用

完整流程是 **扫描 → 分析 → 渲染** 三步：

### 1. 扫描（只读）

```bash
python3 scripts/scan.py > /tmp/storage_scan.json
```

自动识别操作系统，扫描高占用位置（macOS：`$HOME`、`~/Library`、各类缓存 / 容器 / 应用支持、`/Applications`、开发者缓存等；Windows：用户配置文件、AppData、Temp、Program Files、开发者缓存、各盘概览）。输出含 `system` / `groups` / `denied` / `generated_at` / `scan_seconds`；权限不足的目录会出现在 `denied` 里。

### 2. 分析

由 Claude 读取扫描结果与对应平台参考（`references/macos.md` 或 `references/windows.md`），产出一份分析 JSON（绿 / 黄 / 红分级 + Top5 + 摘要）。Schema 见 `SKILL.md` 与 `scripts/build_report.py` 顶部注释。

### 3. 渲染报告

**静态报告（只读，无操作按钮）：**

```bash
python3 scripts/build_report.py /tmp/storage_analysis.json ~/Desktop/storage-report.html
open ~/Desktop/storage-report.html
```

**服务模式（报告页面带「移废纸篓 / 打开位置」按钮）：**

```bash
python3 scripts/server.py /tmp/storage_analysis.json
```

服务会绑定 `127.0.0.1` 的随机端口、生成随机会话 token，并自动打开浏览器。用完按 `Ctrl+C` 停止，服务一停按钮即失效。

---

## 🗂 项目结构

```
storage-analyzer-safe/
├── SKILL.md                     # Skill 定义、工作流与 Safety Contract
├── scripts/
│   ├── scan.py                  # 只读扫描器（macOS + Windows）
│   ├── build_report.py          # 把分析 JSON 注入模板 → 静态 HTML
│   └── server.py                # 带护栏的本地操作服务（open / trash）
├── assets/
│   └── report_template.html     # 报告 UI 模板（数据占位符在渲染时注入）
└── references/
    ├── macos.md                 # macOS 数据布局与分级参考
    └── windows.md               # Windows 数据布局与分级参考
```

---

## 🧭 分类规则

| 级别 | 含义 | 典型对象 | 报告里能做什么 |
|---|---|---|---|
| 🟢 绿 | 纯缓存 / 临时 / 可再生 | pip·uv·npm·Xcode DerivedData、安装包残留、构建产物 | 可一键移废纸篓（删了会自动重建） |
| 🟡 黄 | 用户数据 / 应用托管数据，需判断 | 文档、离线媒体、项目目录、聊天数据、浏览器 Profile、VM 镜像 | 打开位置自查；仅核实过的安全子路径才给移废纸篓 |
| 🔴 红 | 想回收但不该手删 | 大型应用、重复应用、核心应用数据 | 只「在文件管理器里打开 / 选中」，引导走正规卸载 |

系统文件、APFS 快照等通常不上灯，归入「系统及其他」，相关建议写进报告的「长期优化建议」。

---

## 💻 平台支持

- **macOS**：主要目标平台，使用系统工具（`du` / `diskutil` / `sw_vers` / `osascript` / `open`）。删除走 `osascript` 调访达入废纸篓（首次会弹自动化授权），失败时回退到 `~/.Trash` 移动。
- **Windows**：扫描与回收站支持（`ctypes` 调 `SHFileOperationW`，`FOF_ALLOWUNDO`）已实现，但**标注为实验性**，应在真实 Windows 机器上验证后再依赖。
- **其他平台**：`scan.py` 会返回 `unsupported_platform`，不执行扫描。

---

## 📋 依赖

- **Python 3.7+**，仅标准库，无需 `pip install`。
- macOS 依赖系统自带命令行工具（默认即有）。
- Windows 需要 `python` 或 `py -3` 可用。

---

## ⚠️ 隐私与注意事项

- **报告含敏感信息**：生成的 HTML 内联了完整的文件路径、用户名、系统信息与目录结构。分享报告前请确认你愿意公开这些内容，或先脱敏。
- **大小均为估算**：报告里的容量是估算值；不要把可能重叠的扫描组（`home` / `library` / `caches` / 应用支持等）简单相加。
- **保留路径原样**：分析与展示时不要翻译路径字符串或改写命令。
- **服务模式按需开启**：只在确实需要网页操作时才启动 `server.py`，用完即关。

---

## 📄 License

本仓库当前未附带 LICENSE 文件。若要开源发布，建议补一个（如 MIT）以明确使用条款。
