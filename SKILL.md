---
name: storage-analyzer-safe
description: >
  macOS / Windows storage analyzer for disk-space triage. Use when the user asks
  about storage, disk usage, a full drive, cleanup opportunities, caches, or
  "内存满了" in the common colloquial sense of storage, not RAM. The default
  workflow is read-only: scan focused high-impact locations, classify cleanup
  candidates, and generate an HTML report. An optional local service can open
  allowlisted locations or move allowlisted cleanup paths to Trash/Recycle Bin;
  it never performs irreversible rm/delete.
---

# Storage Analyzer Safe

Analyze disk usage, classify cleanup candidates, and generate an HTML report.
This skill is agent-driven: `scan.py` gathers raw data, then the agent creates
the analysis JSON that `build_report.py` or `server.py` renders.

## Safety Contract

- Default mode is read-only: run scanners, inspect metadata, and generate a
  static report. Do not start `server.py` unless the user wants webpage actions.
- Optional service mode is not read-only, but it only supports `open` and
  `trash`. There is no direct-delete/rm path, no empty-Trash action, and no
  uninstall action.
- Only put specific, reviewed cache/temp child paths in `trash_paths`. Never put
  `$HOME`, `~/Desktop`, `~/Documents`, `~/Downloads`, `~/Library`, or broad user
  data folders in `trash_paths`.
- Treat every release number as an estimate. Do not add overlapping scan groups
  together; `home`, `library`, `caches`, and app-support groups can overlap.
- Preserve paths and commands exactly. Do not translate path strings.

## Workflow

### 1. Scan

```bash
python3 scripts/scan.py > /tmp/storage_scan.json
```

The scanner auto-detects the OS.

- macOS: focused scan of high-impact locations such as `$HOME`, `~/Library`,
  caches, containers, app support, applications, downloads, developer caches,
  `/Library`, and `/Users/Shared`.
- Windows: experimental scan of the user profile, AppData, temp, downloads,
  Program Files, developer caches, and all drive summaries.

The output includes `system`, `groups`, `denied`, `generated_at`, and
`scan_seconds`. Permission gaps appear in `denied`; mention them in the report.

### 2. Analyze

Read the platform reference matching `system.os`:

- macOS: `references/macos.md`
- Windows: `references/windows.md`

Use `/tmp/storage_scan.json` to produce an analysis JSON with this shape:

```json
{
  "generated_at": "2026-06-02 12:00:00",
  "scan_seconds": 42.1,
  "system": {},
  "top5": [{"rank": 1, "tier": "green", "size": "约 1.2 GB", "type": "开发缓存", "name": "uv cache", "path": "...", "note": "..."}],
  "green": [{"name": "...", "path": "...", "size_estimate": "约 1.2 GB", "kill_processes": [], "trash_paths": ["..."], "commands": []}],
  "yellow": [{"name": "...", "path": "...", "size": "约 4.0 GB", "content_profile": "...", "why_manual": "...", "disposal": "...", "risk": "...", "trash_paths": [], "open_note": "..."}],
  "red": [{"name": "...", "path": "...", "size": "约 8.0 GB", "why_keep": "...", "indirect_release": "...", "auto_reclaim": "...", "app_paths": []}],
  "denied": [],
  "summary": {"overview": "...", "tier_stats": {"green": "约 1.2 GB", "yellow": "约 4.0 GB", "red": "约 8.0 GB"}, "priority": [], "long_term": []}
}
```

Classification rules:

- Green: pure caches, temp files, installer leftovers, build artifacts, and
  clearly regenerable data. Green items should include `trash_paths`, but only
  for specific safe child paths.
- Yellow: user data or app-managed data that needs judgment, such as documents,
  offline media, project folders, chat data, browser profiles, and VM images.
  Give a content profile, a manual disposal path, and risk notes. Only include
  `trash_paths` for verified safe subpaths; otherwise rely on `path` for opening.
- Red: items a user may want to reclaim but should not hand-delete through the
  report, such as large apps, duplicate apps, or core app data. Provide concrete
  uninstall or app-level cleanup steps. Use `app_paths` only for opening.
- System files and APFS snapshots usually have no direct cleanup decision. Put
  system-level suggestions in `summary.long_term`, not in red cards.

### 3. Render

Default static report:

```bash
python3 scripts/build_report.py /tmp/storage_analysis.json ~/Desktop/storage-report.html
open ~/Desktop/storage-report.html
```

Optional local service with webpage actions:

```bash
python3 scripts/server.py /tmp/storage_analysis.json
```

`server.py` binds to `127.0.0.1` on a random port and uses a random session
token. It realpath-checks all request paths against operation allowlists, limits
trash actions to safe paths under `$HOME`, and only allows app-directory paths
for `open`. The browser confirms every action.

### 4. Report Back

In chat, summarize the estimated reclaimable space, the top 2-3 recommended
actions, and the highest-risk item. Keep details in the HTML report.

## Dependencies

- Python 3 standard library only.
- macOS uses system tools: `du`, `diskutil`, `sw_vers`, `osascript`, and `open`.
- Windows needs Python 3 available as `python` or `py -3`. Windows scanning and
  Recycle Bin support are implemented but should be treated as experimental
  until verified on a real Windows machine.
