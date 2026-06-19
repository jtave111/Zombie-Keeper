#!/usr/bin/env python3
"""ZombieKeeper — Platform Launcher"""

import os, sys, time, random, shutil, subprocess, argparse
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

ROOT       = Path(__file__).parent.resolve()
API_DIR    = ROOT / "ZombieKeeper-Api"
CLIENT_DIR = ROOT / "ZombieKeeper-Client"
ARSENAL    = ROOT / "ZombieKeeper-Arsenal"
API_JAR    = API_DIR / "target" / "Zombie-Keeper-0.0.1-SNAPSHOT.jar"

con = Console()

# ─── Palette ──────────────────────────────────────────────────────────────────
C_RED = "#e05c6e"; C_GRN = "#33a84a"; C_CYN = "#5a96d4"
C_GLD = "#c8a84b"; C_PRP = "#a07fd4"; C_WHT = "#cccccc"
C_GRY = "#555555"; C_DGY = "#2a2a2a"; C_BLK = "#111111"

# ─── Log helpers ──────────────────────────────────────────────────────────────
def _row(icon: str, ic: str, msg: str, mc: str):
    t = Text()
    t.append(f"  [{icon}]", style=f"bold {ic}")
    t.append(f"  {msg}", style=mc)
    con.print(t)

def ok(m):   _row("+", C_GRN, m, C_GRY)
def info(m): _row("*", C_CYN, m, C_GRY)
def warn(m): _row("!", C_GLD, m, C_GLD)
def err(m):  _row("-", C_RED, m, C_RED)

def kv(key: str, val: str, vc: str = C_GRY):
    t = Text()
    t.append(f"      {key:<18}", style=C_DGY)
    t.append(val, style=vc)
    con.print(t)

def section(title: str, color: str = C_RED):
    con.print()
    con.print(Rule(Text(f" {title} ", style=f"bold {color}"), style=C_DGY))
    con.print()

# ─── Skull ────────────────────────────────────────────────────────────────────
# Screaming skull made entirely of ▐ pixel blocks, matching the reference image:
# oval cranium → hollow eye sockets → wide open mouth → teeth row.
SKULL_ART = [
    "              ▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐",
    "           ▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐",
    "         ▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐",
    "        ▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐▐▐░░░         ░▐▐▐░         ░░░▐▐▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐▐               ▐▐▐▐               ▐▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐                 ▐▐▐▐                 ▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐                 ▐▐▐▐                 ▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐▐               ▐▐▐▐               ▐▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐▐▐░░░         ░▐▐▐░         ░░░▐▐▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐",
    "        ▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐",
    "         ░▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐░",
    "       ▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐░░░             ░░░▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐▐▐▐▐▐▐░                       ░▐▐▐▐▐▐▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐▐▐▐▐░                           ░▐▐▐▐▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐▐▐░                               ░▐▐▐▐▐▐▐▐",
    "       ▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐▐",
    "       ▐▐▐░░ ▐▐▐░░ ▐▐▐▐░░ ▐▐▐▐░░ ▐▐▐▐░░ ▐▐▐░░ ▐▐▐░░ ▐▐▐",
    "       ▐▐▐░░ ▐▐▐░░ ▐▐▐▐░░ ▐▐▐▐░░ ▐▐▐▐░░ ▐▐▐░░ ▐▐▐░░ ▐▐▐",
]

# per-row shading — top bright, cheeks/jaw slightly dimmer
_ROW_SHADE = [
    "#888","#999","#aaa","#bbb","#ccc","#ccc","#ccc",
    "#ccc","#bbb","#bbb","#bbb","#bbb","#ccc",
    "#ccc","#bbb","#aaa",
    "#bbb","#aaa","#aaa","#999",
    "#ccc","#888","#777",
]

GLITCH_CHARS = "!@#%^&*|/\\<>?█▓▒░╔╗╚╝║═▲▼◄►▪▀▄"

def _skull_row_text(idx: int) -> Text:
    shade = _ROW_SHADE[idx] if idx < len(_ROW_SHADE) else "#888"
    t = Text()
    for ch in SKULL_ART[idx]:
        if ch == "▐":
            t.append(ch, style=shade)
        elif ch in ("░","▒"):
            t.append(ch, style="#333")
        else:
            t.append(ch)
    return t

def animate_skull():
    """Row-by-row reveal: each row shows 2 glitch frames then the real row.
    Uses carriage-return (\r) per row — no multi-line cursor math needed."""
    width = con.width
    con.print()
    for i, art in enumerate(SKULL_ART):
        pad = max(0, (width - len(art)) // 2)
        prefix = " " * pad
        # two rapid glitch frames on this row
        for _ in range(2):
            g = "".join(
                " " if ch == " " else random.choice(GLITCH_CHARS)
                for ch in art
            )
            sys.stdout.write(f"\r\033[K\033[90m{prefix}{g}\033[0m")
            sys.stdout.flush()
            time.sleep(0.018)
        # clear the glitch frame, then rich-print the real row (adds newline)
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        con.print(Align.center(_skull_row_text(i)))
        time.sleep(0.032)
    con.print()

# ─── Glitch title ─────────────────────────────────────────────────────────────
def glitch_title(text: str, color: str, steps: int = 12, delay: float = 0.035):
    width = con.width
    for step in range(steps + 1):
        pct = step / steps
        t = Text()
        for i, ch in enumerate(text):
            if ch == " ":
                t.append("  ")
            elif i / len(text) < pct:
                t.append(ch, style=f"bold {color}")
            else:
                t.append(random.choice(GLITCH_CHARS), style=C_DGY)
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        # Print without newline by using end=""
        con.print(Align.center(t), end="")
        time.sleep(delay)
    # final with newline
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()
    con.print(Align.center(Text(text, style=f"bold {color}")))

# ─── Boot sequence ────────────────────────────────────────────────────────────
BOOT_LINES = [
    (C_BLK, "BIOS 2.1 — ZombieKeeper Corp.",          "[  OK  ]"),
    (C_BLK, "Initializing memory controller  ",        "[  OK  ]"),
    (C_DGY, "Loading kernel modules          ",        "[  OK  ]"),
    (C_DGY, "Mounting encrypted storage      ",        "[  OK  ]"),
    (C_DGY, "Resolving network interfaces    ",        "[  OK  ]"),
    (C_GRY, "Verifying operator credentials  ",        "[  OK  ]"),
    (C_GRY, "Loading C2 configuration        ",        "[  OK  ]"),
    (C_GRY, "Bypassing endpoint monitoring   ",        "[ SKIP ]"),
    (C_WHT, "Establishing encrypted channel  ",        "[  OK  ]"),
    (C_RED, "ZOMBIE KEEPER OS READY          ",        "[ARMED ]"),
]

def boot_sequence():
    con.print()
    for color, label, tag in BOOT_LINES:
        t = Text()
        t.append(f"  {label}", style=color)
        tc = C_GRN if "OK" in tag else C_GLD if "SKIP" in tag else C_RED
        t.append(f"  {tag}", style=f"bold {tc}")
        con.print(t)
        time.sleep(0.045 + random.uniform(0, 0.025))
    con.print()

# ─── System checks ────────────────────────────────────────────────────────────
def run_checks():
    results = []
    checks = [
        ("Java 21+",      ["java", "-version"],  lambda o: any(v in o for v in ["21","22","23","24","25"])),
        ("Node.js",       ["node", "--version"],  lambda o: o.startswith("v")),
        ("Rust / Cargo",  ["cargo", "--version"], lambda o: "cargo" in o),
        ("Maven Wrapper", None, None),
        ("API .env",      None, None),
        ("API JAR",       None, None),
    ]
    for label, cmd, val in checks:
        if label == "Maven Wrapper":
            ok_ = (API_DIR / "mvnw").exists()
            results.append((label, ok_, "found" if ok_ else "not found")); continue
        if label == "API .env":
            f = API_DIR / ".env"
            results.append((label, f.exists(), str(f) if f.exists() else "MISSING — copy .env.example")); continue
        if label == "API JAR":
            results.append((label, API_JAR.exists(), "built" if API_JAR.exists() else "not built  →  --build")); continue
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            out = (r.stdout + r.stderr).strip()
            found = val(out)
            results.append((label, found, out.split("\n")[0][:44] if found else "not found"))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            results.append((label, False, "not installed"))
    return results

def show_checks():
    section("SYSTEM CHECKS", C_CYN)
    with Progress(SpinnerColumn(spinner_name="dots2", style=C_RED),
                  TextColumn("  [dim]scanning...[/dim]"),
                  transient=True, console=con) as p:
        p.add_task("", total=None)
        time.sleep(0.4)
        results = run_checks()

    table = Table(box=None, padding=(0, 1), show_header=False, expand=False)
    table.add_column(width=5,  justify="center")
    table.add_column(width=16)
    table.add_column()
    for label, good, detail in results:
        icon = Text("[+]" if good else "[-]", style=f"bold {C_GRN if good else C_RED}")
        table.add_row(icon, Text(label, style=C_GRY), Text(detail[:54], style=C_GRN if good else C_RED))
    con.print(Align.center(table))
    con.print()

# ─── Menu ─────────────────────────────────────────────────────────────────────
MENU = [
    ("1", "Full Stack",    "API + Client desktop",  C_GRN),
    ("2", "API Only",      "Spring Boot :8080",      C_CYN),
    ("3", "Client Only",   "Tauri dev mode",         C_PRP),
    ("4", "Full + Build",  "Compile API first",      C_GLD),
    ("5", "Arsenal Build", "C++17 cmake tools",      C_CYN),
    ("0", "Exit",          "",                       C_RED),
]

def show_menu() -> str:
    section("LAUNCH MODE", C_RED)
    for key, name, desc, color in MENU:
        t = Text()
        t.append(f"    [{key}]", style=f"bold {C_DGY}")
        t.append(f"  {name:<20}", style=f"bold {color}")
        if desc: t.append(f"  {desc}", style=C_DGY)
        con.print(t)
    con.print()
    t = Text(); t.append("  ▶ ", style=C_RED)
    con.print(t, end="")
    try:
        return input().strip()
    except (EOFError, KeyboardInterrupt):
        return "0"

# ─── .env loader ──────────────────────────────────────────────────────────────
def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    f = API_DIR / ".env"
    if not f.exists():
        return env
    for line in f.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip().strip('"').strip("'")
            env[k] = v; os.environ[k] = v
    return env

# ─── Build API ────────────────────────────────────────────────────────────────
def build_api():
    section("BUILD API", C_GLD)
    info("mvn clean package -DskipTests")
    with Progress(SpinnerColumn(spinner_name="bouncingBall", style=C_RED),
                  TextColumn("  [dim]compiling...[/dim]"),
                  TimeElapsedColumn(), console=con, transient=True) as p:
        p.add_task("", total=None)
        r = subprocess.run(["./mvnw","clean","package","-DskipTests","-q"],
                           cwd=str(API_DIR), capture_output=True, text=True)
    if r.returncode == 0:
        ok(f"Build complete  →  {API_JAR.name}")
    else:
        err("Build failed:")
        for line in r.stderr.splitlines()[-20:]:
            con.print(Text(f"      {line}", style=C_DGY))
        sys.exit(1)

# ─── API ──────────────────────────────────────────────────────────────────────
def start_api(env: dict) -> "subprocess.Popen | None":
    if not API_JAR.exists():
        err(f"JAR not found: {API_JAR}"); info("Run:  ./ZombieKeeper.sh --build"); return None
    port = env.get("SERVER_PORT", "8080")
    proc = subprocess.Popen(["java","-jar",str(API_JAR)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(API_DIR))
    ok("Spring Boot started")
    kv("endpoint", f"http://localhost:{port}", C_CYN)
    kv("pid",      str(proc.pid))
    return proc

def wait_api(env: dict, timeout: int = 30) -> bool:
    port = env.get("SERVER_PORT", "8080")
    # raw ANSI — avoids split rich markup tags across print() calls
    sys.stdout.write("\033[90m      waiting")
    sys.stdout.flush()
    for _ in range(timeout):
        try:
            r = subprocess.run(["curl","-sf",f"http://localhost:{port}/actuator/health"],
                               capture_output=True, timeout=2)
            if r.returncode == 0:
                sys.stdout.write("\033[0m\n"); sys.stdout.flush()
                ok("API healthy  ✓"); return True
        except Exception:
            pass
        sys.stdout.write("\033[90m.\033[0m"); sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\033[0m\n"); sys.stdout.flush()
    warn("Health check timed out — API may still be starting")
    return False

# ─── Client ───────────────────────────────────────────────────────────────────
def start_client():
    if not (CLIENT_DIR / "node_modules").exists():
        warn("node_modules missing — running npm install...")
        subprocess.run(["npm","install","--silent"], cwd=str(CLIENT_DIR), check=True)
        ok("Dependencies ready.")
    con.print()
    t = Text()
    t.append("  ┌──────────────────────────────────────────────┐\n", style=C_DGY)
    t.append("  │  ", style=C_DGY); t.append("[*] Desktop window opening...             ", style=C_GRY); t.append("│\n", style=C_DGY)
    t.append("  │  ", style=C_DGY); t.append("[*] Hot-reload active                     ", style=C_GRY); t.append("│\n", style=C_DGY)
    t.append("  │  ", style=C_DGY); t.append("[!] Ctrl+C to stop                        ", style=C_GLD); t.append("│\n", style=C_DGY)
    t.append("  └──────────────────────────────────────────────┘", style=C_DGY)
    con.print(t); con.print()
    subprocess.run(["npm","run","tauri","dev"], cwd=str(CLIENT_DIR))

# ─── Arsenal ──────────────────────────────────────────────────────────────────
def build_arsenal():
    section("ARSENAL BUILD", C_CYN)
    info("make  (C++17, CMake)")
    with Progress(SpinnerColumn(spinner_name="aesthetic", style=C_CYN),
                  TextColumn("  [dim]building...[/dim]"),
                  TimeElapsedColumn(), console=con, transient=True) as p:
        p.add_task("", total=None)
        r = subprocess.run(["make"], cwd=str(ARSENAL), capture_output=True, text=True)
    if r.returncode == 0:
        ok("Arsenal built.")
        t = Text(); t.append("      setcap  →  ", style=C_DGY)
        t.append(f"sudo cmake --build {ARSENAL}/build --target setcap", style=C_GLD)
        con.print(t)
    else:
        err("Build failed:")
        for line in (r.stderr or r.stdout).splitlines()[-15:]:
            con.print(Text(f"      {line}", style=C_DGY))

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    pa = argparse.ArgumentParser(add_help=False)
    pa.add_argument("--build",    action="store_true")
    pa.add_argument("--api-only", action="store_true", dest="api_only")
    pa.add_argument("--client",   action="store_true")
    pa.add_argument("--arsenal",  action="store_true")
    pa.add_argument("--help","-h",action="store_true")
    args = pa.parse_args()

    if args.help:
        con.print(Panel(
            Text.assemble(
                ("./ZombieKeeper.sh ",f"bold {C_WHT}"),("[options]\n\n",C_GRY),
                ("  --build     ",f"bold {C_GRN}"),("Compile API (mvn package)\n",C_GRY),
                ("  --api-only  ",f"bold {C_CYN}"),("Start API only\n",C_GRY),
                ("  --client    ",f"bold {C_PRP}"),("Start desktop client only\n",C_GRY),
                ("  --arsenal   ",f"bold {C_CYN}"),("Build C++ Arsenal tools\n",C_GRY),
                ("  --help      ",f"bold {C_DGY}"),("This message",C_GRY),
            ),
            title=Text("ZombieKeeper",style=f"bold {C_RED}"),border_style=C_DGY,
        ))
        return

    os.system("clear")
    con.print()
    boot_sequence()
    animate_skull()
    glitch_title("Z  O  M  B  I  E  K  E  E  P  E  R", C_RED, steps=14, delay=0.033)
    con.print()
    con.print(Align.center(Text("C2 Framework  ·  Red Team  ·  Blue Team  ·  CTF", style=C_DGY)))
    con.print(Align.center(Text("Spring Boot 4  ·  Tauri 2  ·  React 19  ·  C++17 Arsenal", style=C_BLK)))
    con.print()

    show_checks()
    env = load_env()

    have = any([args.build, args.api_only, args.client, args.arsenal])
    mode = ("5" if args.arsenal else "2" if args.api_only else "3" if args.client
            else "4" if args.build else "1") if have else show_menu()

    api_proc = None

    if mode == "0":
        con.print(); con.print(Align.center(Text("[ exited ]", style=C_DGY))); con.print(); return
    if mode == "5":
        build_arsenal(); return
    if mode == "4" or args.build:
        build_api()
    if mode in ("1","2","4"):
        section("API", C_RED)
        api_proc = start_api(env)
        if api_proc: wait_api(env)
    if mode in ("1","3","4"):
        section("CLIENT", C_RED)
        try: start_client()
        except KeyboardInterrupt: pass
    if mode == "2" and api_proc:
        con.print()
        t = Text(); t.append("  [*]  API running.  ",f"bold {C_GRN}")
        t.append("Ctrl+C",f"bold {C_WHT}"); t.append(" to stop.",C_GRY); con.print(t)
        try: api_proc.wait()
        except KeyboardInterrupt: pass

    if api_proc and api_proc.poll() is None:
        con.print()
        t = Text(); t.append(f"  [*]  Stopping API (PID {api_proc.pid})...", C_GLD); con.print(t)
        api_proc.terminate()
        try: api_proc.wait(timeout=10)
        except subprocess.TimeoutExpired: api_proc.kill()
        ok("API stopped.")

    con.print(); con.print(Align.center(Text("[ ZombieKeeper exited ]", style=C_DGY))); con.print()

if __name__ == "__main__":
    main()
