#!/usr/bin/env python3
"""Serve the storage report with a guarded local action API (macOS + Windows).

Starts on 127.0.0.1 + a random port + a random per-session token, serves the
interactive report, and exposes POST /action to open allowlisted paths or move
allowlisted cleanup paths to Trash. Stop with Ctrl+C.

Usage:
    server.py <analysis.json>

SAFETY MODEL — read before changing:
- Allowlist: only paths listed in this report's `trash_paths`, yellow `path`, or
  red `app_paths` are accepted for their matching operation. Every request path
  is realpath-resolved and must be in the operation allowlist and inside an
  approved root. Anything else is rejected.
- Bound to 127.0.0.1 only; every POST requires the session token; Host header
  must be 127.0.0.1 (blocks DNS-rebinding from a malicious page).
- Two modes: "open" and "trash" only. There is no irreversible rm mode.
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "..", "assets", "report_template.html")
HOME = os.path.realpath(os.path.expanduser("~"))
TOKEN = secrets.token_urlsafe(24)

DATA = {}
TPL = ""
TRASH_ALLOW = set()
OPEN_ALLOW = set()


def expand(p):
    return os.path.realpath(os.path.expanduser(p))


def safe_json(obj):
    """JSON safe to inline inside a <script> block."""
    return (json.dumps(obj, ensure_ascii=False)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def under_any(path, roots):
    for root in roots:
        try:
            if root and os.path.commonpath([path, root]) == root:
                return True
        except ValueError:
            continue
    return False


def local_host_from_header(value):
    host = (value or "").strip().lower()
    if not host:
        return ""
    if host.startswith("["):
        return host.split("]", 1)[0].lstrip("[")
    return host.split(":", 1)[0]


def is_allowed_local_host(value):
    return local_host_from_header(value) in ("127.0.0.1", "localhost")


def is_allowed_origin(value):
    if not value:
        return True
    parsed = urlparse(value)
    return parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost")


def is_json_content_type(value):
    return (value or "").split(";", 1)[0].strip().lower() == "application/json"


def open_roots():
    roots = [HOME]
    if sys.platform == "darwin":
        roots.append(expand("/Applications"))
    elif sys.platform.startswith("win"):
        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            value = os.environ.get(env_name)
            if value:
                roots.append(expand(value))
    return roots


def trash_roots():
    return [HOME]


def protected_trash_paths():
    names = ("Desktop", "Documents", "Movies", "Music", "Pictures", "Public")
    return {HOME, *(expand(os.path.join(HOME, name)) for name in names)}


def sensitive_trash_roots():
    names = (
        ".ssh", ".aws", ".gnupg", ".kube", ".config", ".password-store",
        "Library/Keychains", "Library/Application Support", "Library/Containers",
        "Library/Group Containers",
    )
    return [expand(os.path.join(HOME, name)) for name in names]


def allowed_trash_roots():
    if sys.platform == "darwin":
        roots = (
            "Library/Caches",
            ".cache",
            ".npm",
            ".pnpm-store",
            ".gradle/caches",
            ".m2/repository",
            ".cargo/registry",
            ".cargo/git",
            "Library/pnpm",
            "Library/Developer/Xcode/DerivedData",
            "Library/Developer/Xcode/iOS DeviceSupport",
            "Library/Developer/CoreSimulator/Caches",
            "go/pkg",
        )
    elif sys.platform.startswith("win"):
        local = os.environ.get("LOCALAPPDATA", os.path.join(HOME, "AppData", "Local"))
        roots = (
            os.environ.get("TEMP", os.path.join(local, "Temp")),
            os.path.join(local, "Temp"),
            os.path.join(local, "pip", "Cache"),
            os.path.join(local, "Yarn"),
            os.path.join(local, "uv"),
            os.path.join(local, "ms-playwright"),
            os.path.join(local, "go-build"),
            ".cache",
            ".npm",
            ".gradle/caches",
            ".m2/repository",
            ".nuget/packages",
            ".cargo/registry",
            ".cargo/git",
        )
    else:
        roots = ()
    return [expand(root if os.path.isabs(root) else os.path.join(HOME, root)) for root in roots]


def safe_download_artifact(path):
    downloads = expand(os.path.join(HOME, "Downloads"))
    if not under_any(path, [downloads]) or os.path.isdir(path):
        return False
    return os.path.splitext(path)[1].lower() in (
        ".dmg", ".pkg", ".mpkg", ".zip", ".tar", ".gz", ".tgz", ".xz",
        ".msi", ".exe",
    )


def trash_path_is_safe(path):
    if not under_any(path, trash_roots()) or path in protected_trash_paths():
        return False
    if under_any(path, sensitive_trash_roots()):
        return False
    return under_any(path, allowed_trash_roots()) or safe_download_artifact(path)


def broad_trash_reject_reason(path):
    if not under_any(path, trash_roots()):
        return "路径越界"
    if path in protected_trash_paths() or under_any(path, sensitive_trash_roots()):
        return "路径过大或受保护"
    if not (under_any(path, allowed_trash_roots()) or safe_download_artifact(path)):
        return "路径不属于允许的缓存或临时位置"
    return ""


def load(src):
    with open(src, encoding="utf-8") as f:
        data = json.load(f)
    with open(TEMPLATE, encoding="utf-8") as f:
        tpl = f.read()
    # 三套白名单，权限从严到宽：
    #   trash = 绿灯 + 橙灯 trash_paths（只移废纸篓，不直接删）
    #   open  = trash 全集 + 橙灯 path + 红灯 app_paths（仅"在文件管理器打开"，非破坏性）
    trash_allow, open_allow = set(), set()
    for it in data.get("green", []):
        for p in (it.get("trash_paths") or []):
            rp = expand(p)
            if trash_path_is_safe(rp):
                trash_allow.add(rp); open_allow.add(rp)
    for it in data.get("yellow", []):
        for p in (it.get("trash_paths") or []):
            rp = expand(p)
            if trash_path_is_safe(rp):
                trash_allow.add(rp); open_allow.add(rp)
        if it.get("path"):
            rp = expand(it["path"])
            if os.path.exists(rp) and under_any(rp, open_roots()):
                open_allow.add(rp)
    # 红灯只允许"打开"（应用本体在 /Applications，删除让用户在访达里自己卸）
    for it in data.get("red", []):
        for p in (it.get("app_paths") or []):
            rp = expand(p)
            if os.path.exists(rp) and under_any(rp, open_roots()):
                open_allow.add(rp)
    return data, tpl, trash_allow, open_allow


def move_to_trash(path):
    if sys.platform == "darwin":
        _trash_macos(path)
    elif sys.platform.startswith("win"):
        _trash_windows(path)
    else:
        raise OSError("移到废纸篓仅支持 macOS / Windows")


def _trash_macos(path):
    # osascript Finder delete -> macOS Trash, recoverable. First run may prompt
    # for Finder automation permission. Fall back to ~/.Trash move if it fails.
    script = 'tell application "Finder" to delete (POSIX file %s as alias)' % json.dumps(path)
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
    if r.returncode != 0:
        base = os.path.basename(path.rstrip("/")) + "." + time.strftime("%H%M%S")
        dest = os.path.join(HOME, ".Trash", base)
        suffix = 1
        while os.path.exists(dest):
            suffix += 1
            dest = os.path.join(HOME, ".Trash", f"{base}.{suffix}")
        shutil.move(path, dest)


def _trash_windows(path):
    # Send to Recycle Bin via SHFileOperationW with FOF_ALLOWUNDO (stdlib ctypes).
    # UNTESTED on this build — verify on a real Windows machine.
    import ctypes
    from ctypes import wintypes

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_uint16),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    FO_DELETE = 3
    FOF_ALLOWUNDO = 0x0040
    FOF_NOCONFIRMATION = 0x0010    # 送回收站时不弹确认，正常流程不打扰
    FOF_WANTNUKEWARNING = 0x4000   # 但无法送回收站、要永久删除时仍弹警告，杜绝静默 nuke
    op = SHFILEOPSTRUCTW()
    op.wFunc = FO_DELETE
    op.pFrom = os.path.abspath(path) + "\x00\x00"  # double-null terminated list
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_WANTNUKEWARNING
    rc = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    if rc != 0:
        raise OSError("SHFileOperation failed (code %d)" % rc)
    if op.fAnyOperationsAborted:
        raise OSError("操作已取消：该文件可能无法移入回收站")


def open_in_file_manager(path):
    # 非破坏性：在访达 / 资源管理器里打开该位置，方便用户自己审查删除
    target = path if os.path.isdir(path) else os.path.dirname(path)
    if sys.platform == "darwin":
        # .app 是 bundle，对它用 open 会"启动应用"而非显示；必须用 open -R 在访达里选中。
        if target.rstrip("/").endswith(".app"):
            r = subprocess.run(["open", "-R", target], capture_output=True, text=True)
            if r.returncode != 0:
                raise OSError((r.stderr or "open -R 失败").strip())
            return
        # 普通文件夹：先试直接打开看内容；沙盒容器（如微信）open 会报 -10814，
        # 退回 open -R 在父目录里选中它。两者都失败才算错。
        r = subprocess.run(["open", target], capture_output=True, text=True)
        if r.returncode != 0:
            r2 = subprocess.run(["open", "-R", target], capture_output=True, text=True)
            if r2.returncode != 0:
                raise OSError((r.stderr or r2.stderr or "open 失败").strip())
    elif sys.platform.startswith("win"):
        subprocess.run(["explorer", target])  # explorer 退出码不可靠，不据此判成败
    else:
        raise OSError("打开文件夹仅支持 macOS / Windows")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if not is_allowed_local_host(self.headers.get("Host")):
            self._send(403, "host 不被允许", "text/plain")
            return
        if self.path in ("/", "/index.html"):
            blob = safe_json(DATA)
            cfg = safe_json({"token": TOKEN, "endpoint": "/action"})
            html = TPL.replace("__REPORT_DATA__", blob).replace("__DELETE_CONFIG__", cfg)
            self._send(200, html, "text/html; charset=utf-8")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        if self.path != "/action":
            self._send(404, json.dumps({"ok": False, "error": "not found"}))
            return
        # DNS-rebinding guard: only accept local Host
        if not is_allowed_local_host(self.headers.get("Host")):
            self._send(403, json.dumps({"ok": False, "error": "host 不被允许"}))
            return
        if not is_allowed_origin(self.headers.get("Origin")):
            self._send(403, json.dumps({"ok": False, "error": "origin 不被允许"}))
            return
        referer = self.headers.get("Referer")
        if referer and not is_allowed_origin(referer):
            self._send(403, json.dumps({"ok": False, "error": "referer 不被允许"}))
            return
        if not is_json_content_type(self.headers.get("Content-Type")):
            self._send(415, json.dumps({"ok": False, "error": "仅支持 application/json"}))
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self._send(400, json.dumps({"ok": False, "error": "请求格式错误"}))
            return
        if n < 0 or n > (1 << 20):  # 1 MiB 上限，挡住超大 Content-Length 拖住线程
            self._send(413, json.dumps({"ok": False, "error": "请求体过大"}))
            return
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self._send(400, json.dumps({"ok": False, "error": "请求格式错误"}))
            return
        if not secrets.compare_digest(str(req.get("token") or ""), TOKEN):
            self._send(403, json.dumps({"ok": False, "error": "token 校验失败"}))
            return
        mode = req.get("mode")
        allow = {"trash": TRASH_ALLOW, "open": OPEN_ALLOW}.get(mode)
        if allow is None:
            self._send(400, json.dumps({"ok": False, "error": "未知操作"}))
            return
        done = []
        for p in (req.get("paths") or []):
            rp = expand(p)
            if rp not in allow:
                self._send(403, json.dumps({"ok": False, "error": "路径不在白名单：%s" % p}))
                return
            # 二级护栏：trash 仅限用户目录下的非顶层路径；open 允许用户目录和平台应用目录。
            roots = trash_roots() if mode == "trash" else open_roots()
            if not under_any(rp, roots):
                self._send(403, json.dumps({"ok": False, "error": "路径越界：%s" % p}))
                return
            if mode == "trash" and not trash_path_is_safe(rp):
                reason = broad_trash_reject_reason(rp) or "路径过大或受保护"
                self._send(403, json.dumps({"ok": False, "error": "%s：%s" % (reason, p)}))
                return
            try:
                if mode == "open":
                    open_in_file_manager(rp)
                elif not os.path.exists(rp):
                    pass  # already gone, treat as success
                elif mode == "trash":
                    move_to_trash(rp)
                done.append(p)
            except Exception as e:
                self._send(500, json.dumps({"ok": False, "error": str(e)}))
                return
        self._send(200, json.dumps({"ok": True, "done": done}))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    global DATA, TPL, TRASH_ALLOW, OPEN_ALLOW
    DATA, TPL, TRASH_ALLOW, OPEN_ALLOW = load(sys.argv[1])
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    url = "http://127.0.0.1:%d/" % port
    print("报告服务已启动：" + url)
    print("可移废纸篓 %d 项 | 可打开位置 %d 项 | 页面操作前会二次确认" % (len(TRASH_ALLOW), len(OPEN_ALLOW)))
    print("用完按 Ctrl+C 停止服务（服务关掉后按钮即失效）")
    webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止服务。")


if __name__ == "__main__":
    main()
