import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

app = typer.Typer(help="N-VIEW - Human-first Nmap workflow with AI reporting.")
console = Console()

APP_NAME = "N-VIEW"
APP_VERSION = "2.0.0"
AUTHOR = "Fahad Khan (cybe4sent1nel)"
DEVELOPER = "cybe4sent1nel"
PAYPAL = "fahadkhanxyz8816@gmail.com"
TAGLINE = "Professional Network Visibility, Simplified."

AI_SYSTEM_PROMPT = """
You are a senior red-team and blue-team security analyst producing a professional network assessment report.
Always output clean markdown with these sections in order:
1) Executive Summary
2) Scan Scope and Method
3) Attack Surface Overview
4) Findings Table (ID, Severity, Evidence, Risk, Recommendation)
5) Detailed Technical Findings
6) Prioritized Remediation Plan (P1/P2/P3)
7) Validation Checklist
8) Hardening Recommendations
9) Assumptions and Limitations

Rules:
- Base conclusions only on provided scan evidence.
- If confidence is low, say so explicitly.
- Never invent CVEs if not in evidence.
- Prefer actionable remediation with concrete commands/settings where possible.
- Keep language concise, technical, and operator-friendly.
""".strip()

CONFIG_DIR = Path.home() / ".config" / "nview"
CONFIG_FILE = CONFIG_DIR / "config.json"
OUTPUT_DIR = Path.cwd() / "nview-results"
ENV_FILE = Path.cwd() / ".env"

PROVIDER_CEREBRAS = "cerebras"
PROVIDER_OPENROUTER = "openrouter"
DEFAULT_CEREBRAS_MODEL = "qwen-3-235b-a22b-instruct-2507"
DEFAULT_OPENROUTER_MODEL = "openrouter/auto"


@dataclass
class AIConfig:
    provider: str = PROVIDER_CEREBRAS
    model: str = DEFAULT_CEREBRAS_MODEL
    cerebras_api_key: str = ""
    openrouter_api_key: str = ""
    openrouter_model: str = DEFAULT_OPENROUTER_MODEL

    @staticmethod
    def from_dict(data: dict) -> "AIConfig":
        return AIConfig(
            provider=data.get("provider", PROVIDER_CEREBRAS),
            model=data.get("model", DEFAULT_CEREBRAS_MODEL),
            cerebras_api_key=data.get("cerebras_api_key", ""),
            openrouter_api_key=data.get("openrouter_api_key", ""),
            openrouter_model=data.get("openrouter_model", DEFAULT_OPENROUTER_MODEL),
        )

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "model": self.model,
            "cerebras_api_key": self.cerebras_api_key,
            "openrouter_api_key": self.openrouter_api_key,
            "openrouter_model": self.openrouter_model,
        }


@dataclass
class ScanRunResult:
    xml_output: Path
    txt_output: Path
    command: str
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    return_code: int
    stdout: str
    stderr: str


def load_dotenv_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def apply_env_overrides(cfg: AIConfig) -> AIConfig:
    cerebras_key = os.getenv("CEREBRAS_API_KEY", "").strip()
    openrouter_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    cerebras_model = os.getenv("CEREBRAS_MODEL", "").strip()
    openrouter_model = os.getenv("OPENROUTER_MODEL", "").strip()
    provider = os.getenv("NVIEW_DEFAULT_PROVIDER", "").strip().lower()

    if cerebras_key:
        cfg.cerebras_api_key = cerebras_key
    if openrouter_key:
        cfg.openrouter_api_key = openrouter_key
    if cerebras_model:
        cfg.model = cerebras_model
    if openrouter_model:
        cfg.openrouter_model = openrouter_model
    if provider in {PROVIDER_CEREBRAS, PROVIDER_OPENROUTER}:
        cfg.provider = provider
    return cfg


def load_config() -> AIConfig:
    load_dotenv_file(ENV_FILE)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        cfg = AIConfig()
        CONFIG_FILE.write_text(json.dumps(cfg.to_dict(), indent=2), encoding="utf-8")
        return apply_env_overrides(cfg)
    try:
        cfg = AIConfig.from_dict(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
        return apply_env_overrides(cfg)
    except Exception:
        cfg = AIConfig()
        CONFIG_FILE.write_text(json.dumps(cfg.to_dict(), indent=2), encoding="utf-8")
        return apply_env_overrides(cfg)


def save_config(cfg: AIConfig) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg.to_dict(), indent=2), encoding="utf-8")


def mask_secret(secret: str) -> str:
    if not secret:
        return "<not set>"
    if len(secret) < 8:
        return "*" * len(secret)
    return f"{secret[:3]}...{secret[-3:]}"


def print_banner() -> None:
    art = r"""
███╗   ██╗      ██╗   ██╗██╗███████╗██╗    ██╗
████╗  ██║      ██║   ██║██║██╔════╝██║    ██║
██╔██╗ ██║█████╗██║   ██║██║█████╗  ██║ █╗ ██║
██║╚██╗██║╚════╝╚██╗ ██╔╝██║██╔══╝  ██║███╗██║
██║ ╚████║       ╚████╔╝ ██║███████╗╚███╔███╔╝
╚═╝  ╚═══╝        ╚═══╝  ╚═╝╚══════╝ ╚══╝╚══╝
"""
    subtitle = f"[bold white]{APP_NAME} v{APP_VERSION}[/bold white]  [bright_cyan]Developed by {AUTHOR}[/bright_cyan]"
    tagline = f"[bold green]{TAGLINE}[/bold green]"
    sponsor = f"[bold magenta]Sponsor our project[/bold magenta]: {PAYPAL}"
    console.print(
        Panel.fit(
            f"[bold blue]{art}[/bold blue]\n{subtitle}\n{tagline}\n{sponsor}",
            title="N-VIEW Control Console",
            border_style="bright_blue",
        )
    )


def render_ai_report(report_text: str, provider: str) -> None:
    console.print(
        Panel(
            Markdown(report_text),
            title=f"AI Security Report ({provider})",
            border_style="bright_green",
        )
    )


def resolve_nmap_binary() -> Optional[str]:
    in_path = shutil.which("nmap")
    if in_path:
        return in_path
    candidates = [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return None


def detect_platform() -> tuple[str, str]:
    system = platform.system().lower()
    distro = ""
    if system == "linux":
        os_release = Path("/etc/os-release")
        if os_release.exists():
            for line in os_release.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("ID="):
                    distro = line.split("=", 1)[1].strip().strip('"').lower()
                    break
    return system, distro


def manual_nmap_install_commands() -> list[str]:
    system, distro = detect_platform()
    if system == "windows":
        return [
            "winget install -e --id Insecure.Nmap",
            "choco install nmap -y",
            "scoop install nmap",
        ]
    if system == "darwin":
        return ["brew install nmap"]
    if system == "linux":
        if distro in {"ubuntu", "debian", "linuxmint", "kali", "parrot"}:
            return ["sudo apt update && sudo apt install -y nmap"]
        if distro in {"fedora", "rhel", "centos", "rocky", "almalinux"}:
            return ["sudo dnf install -y nmap", "sudo yum install -y nmap"]
        if distro in {"arch", "manjaro"}:
            return ["sudo pacman -S --noconfirm nmap"]
        if distro in {"opensuse", "sles"}:
            return ["sudo zypper install -y nmap"]
        return [
            "sudo apt install -y nmap",
            "sudo dnf install -y nmap",
            "sudo pacman -S --noconfirm nmap",
        ]
    return ["Install Nmap manually from https://nmap.org/download.html"]


def install_attempts_for_nmap() -> list[list[str]]:
    system, _ = detect_platform()
    if system == "windows":
        return [
            ["winget", "install", "-e", "--id", "Insecure.Nmap", "--accept-package-agreements", "--accept-source-agreements"],
            ["choco", "install", "nmap", "-y"],
            ["scoop", "install", "nmap"],
        ]
    if system == "darwin":
        return [["brew", "install", "nmap"]]

    if shutil.which("apt"):
        return [["sudo", "apt", "update"], ["sudo", "apt", "install", "-y", "nmap"]]
    if shutil.which("dnf"):
        return [["sudo", "dnf", "install", "-y", "nmap"]]
    if shutil.which("yum"):
        return [["sudo", "yum", "install", "-y", "nmap"]]
    if shutil.which("pacman"):
        return [["sudo", "pacman", "-S", "--noconfirm", "nmap"]]
    if shutil.which("zypper"):
        return [["sudo", "zypper", "install", "-y", "nmap"]]
    return []


def can_execute_command(cmd: list[str]) -> bool:
    if not cmd:
        return False
    if cmd[0] == "sudo":
        return len(cmd) > 1 and shutil.which("sudo") is not None and shutil.which(cmd[1]) is not None
    return shutil.which(cmd[0]) is not None


def try_install_nmap() -> bool:
    commands = install_attempts_for_nmap()
    if not commands:
        return False

    console.print("[yellow]Nmap missing. Attempting automatic installation...[/yellow]")
    for cmd in commands:
        if not can_execute_command(cmd):
            continue
        console.print(f"[cyan]Trying:[/cyan] {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except Exception:
            continue
        if proc.returncode == 0 and resolve_nmap_binary():
            console.print("[green]Nmap installed successfully.[/green]")
            return True

    return bool(resolve_nmap_binary())


def ensure_nmap(auto_install: bool = True) -> str:
    nmap_bin = resolve_nmap_binary()
    if nmap_bin:
        return nmap_bin

    if auto_install and try_install_nmap():
        nmap_bin = resolve_nmap_binary()
        if nmap_bin:
            return nmap_bin

    manual = "\n".join(f"- {cmd}" for cmd in manual_nmap_install_commands())
    raise typer.BadParameter(
        "Nmap is not installed or not in PATH. Automatic install failed. Install manually and retry:\n"
        f"{manual}"
    )


def install_command_aliases() -> tuple[list[str], list[str]]:
    created: list[str] = []
    notes: list[str] = []
    system, _ = detect_platform()

    if system == "windows":
        bin_dir = Path.home() / "AppData" / "Local" / "nview" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)

        cmd_launcher = (
            "@echo off\r\n"
            "setlocal\r\n"
            "where py >nul 2>nul\r\n"
            "if %ERRORLEVEL%==0 (\r\n"
            "  py -m nview.cli %*\r\n"
            ") else (\r\n"
            "  python -m nview.cli %*\r\n"
            ")\r\n"
            "endlocal\r\n"
        )
        nview_cmd = bin_dir / "nview.cmd"
        nview_cmd.write_text(cmd_launcher, encoding="utf-8")
        created.append(str(nview_cmd))

        n_dash_cmd = bin_dir / "n-view.cmd"
        if n_dash_cmd.exists() or n_dash_cmd.is_symlink():
            n_dash_cmd.unlink()
        try:
            n_dash_cmd.symlink_to(nview_cmd)
            created.append(str(n_dash_cmd))
        except Exception:
            n_dash_cmd.write_text(cmd_launcher, encoding="utf-8")
            created.append(str(n_dash_cmd))
            notes.append("Windows symlink creation for n-view failed; created n-view.cmd launcher instead.")

        current_path = os.environ.get("PATH", "")
        if str(bin_dir).lower() not in current_path.lower():
            notes.append(f"Add this directory to PATH to use commands globally: {bin_dir}")
        return created, notes

    bin_dir = Path.home() / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    launcher = bin_dir / "nview"
    launcher.write_text(
        "#!/usr/bin/env sh\n"
        "if command -v python3 >/dev/null 2>&1; then\n"
        "  exec python3 -m nview.cli \"$@\"\n"
        "fi\n"
        "if command -v python >/dev/null 2>&1; then\n"
        "  exec python -m nview.cli \"$@\"\n"
        "fi\n"
        "echo 'Python interpreter not found. Install Python 3.11+ and retry.' >&2\n"
        "exit 1\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    created.append(str(launcher))

    alias = bin_dir / "n-view"
    if alias.exists() or alias.is_symlink():
        alias.unlink()
    try:
        alias.symlink_to(launcher)
        created.append(str(alias))
    except Exception:
        alias.write_text(
            "#!/usr/bin/env sh\n"
            "if command -v python3 >/dev/null 2>&1; then\n"
            "  exec python3 -m nview.cli \"$@\"\n"
            "fi\n"
            "if command -v python >/dev/null 2>&1; then\n"
            "  exec python -m nview.cli \"$@\"\n"
            "fi\n"
            "echo 'Python interpreter not found. Install Python 3.11+ and retry.' >&2\n"
            "exit 1\n",
            encoding="utf-8",
        )
        alias.chmod(0o755)
        created.append(str(alias))
        notes.append("Symlink creation for n-view failed; created executable wrapper instead.")

    current_path = os.environ.get("PATH", "")
    if str(bin_dir) not in current_path.split(os.pathsep):
        notes.append(f"Add this directory to PATH to use commands globally: {bin_dir}")

    return created, notes


def check_dependencies(auto_fix: bool = False) -> dict:
    system, distro = detect_platform()
    nmap_bin = resolve_nmap_binary()
    nmap_status = "OK" if nmap_bin else "MISSING"

    if auto_fix and not nmap_bin:
        if try_install_nmap():
            nmap_bin = resolve_nmap_binary()
            nmap_status = "OK"

    return {
        "os": system,
        "distro": distro or "n/a",
        "nmap_status": nmap_status,
        "nmap_path": nmap_bin or "not found",
        "manual_install": manual_nmap_install_commands(),
    }


def validate_target(target: str) -> None:
    if not target.strip():
        raise typer.BadParameter("Target cannot be empty.")
    if len(target) > 255:
        raise typer.BadParameter("Target seems invalid (too long).")


def numbered_choice(title: str, options: list[str], default: Optional[int] = None) -> int:
    console.print(f"\n[bold]{title}[/bold]")
    for idx, option in enumerate(options, start=1):
        console.print(f"  [cyan]{idx}[/cyan]. {option}")

    while True:
        raw = Prompt.ask("Select a number", default=str(default) if default else None)
        if not raw.isdigit():
            console.print("[red]Please enter a number.[/red]")
            continue
        value = int(raw)
        if 1 <= value <= len(options):
            return value
        console.print(f"[red]Out of range. Use 1-{len(options)}.[/red]")


def normalize_natural_language(text: str) -> tuple[str, str]:
    normalized = text.lower().strip()
    if not normalized:
        return "-sV --top-ports 100", "Balanced service scan on top 100 ports"
    if any(k in normalized for k in ["ping", "discover", "alive", "host only"]):
        return "-sn", "Host discovery only"
    if any(k in normalized for k in ["quick", "fast", "top", "common"]):
        return "-sV --top-ports 100 -T4", "Quick top ports + service detection"
    if any(k in normalized for k in ["full", "all ports", "complete"]):
        return "-p- -sV -T4", "Full TCP ports + service detection"
    if any(k in normalized for k in ["aggressive", "deep", "os", "traceroute"]):
        return "-A -T4", "Aggressive scan"
    if any(k in normalized for k in ["udp", "dns", "snmp"]):
        return "-sU --top-ports 200", "UDP-focused scan"
    if any(k in normalized for k in ["vuln", "cve", "nse", "exploit"]):
        return "-sV --script vuln", "Vulnerability script scan"
    return "-sV --top-ports 100", "Balanced service scan on top 100 ports"


def choose_scan_profile() -> tuple[str, str]:
    options = [
        "Host discovery only (ping scan)",
        "Quick scan (top 100 ports + service detection)",
        "Full TCP scan (all ports + service detection)",
        "Aggressive scan (OS, scripts, traceroute)",
        "UDP focused scan (top UDP ports)",
        "Vulnerability script scan (NSE vuln)",
        "Natural language mode (describe desired scan)",
        "Custom raw flags",
    ]
    choice = numbered_choice("Select scan type", options, default=2)
    if choice == 1:
        return "-sn", "Host discovery only"
    if choice == 2:
        return "-sV --top-ports 100 -T4", "Quick scan"
    if choice == 3:
        return "-p- -sV -T4", "Full TCP scan"
    if choice == 4:
        return "-A -T4", "Aggressive scan"
    if choice == 5:
        return "-sU --top-ports 200", "UDP focused"
    if choice == 6:
        return "-sV --script vuln", "NSE vulnerability script scan"
    if choice == 7:
        intent = Prompt.ask("Describe the scan in natural language")
        return normalize_natural_language(intent)
    raw = Prompt.ask("Enter custom nmap flags", default="-sV --top-ports 100")
    return raw, "Custom"


def run_scan(target: str, flags: str, output_prefix: Path) -> ScanRunResult:
    nmap_bin = ensure_nmap(auto_install=True)
    validate_target(target)
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    xml_output = output_prefix.with_suffix(".xml")
    txt_output = output_prefix.with_suffix(".txt")

    parsed_flags = shlex.split(flags, posix=False)
    cmd = [nmap_bin] + parsed_flags + ["-oX", str(xml_output), target]
    started_at = datetime.now()
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task_id = progress.add_task("Running Nmap scan...", total=None)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        progress.update(task_id, description="Scan finished")
    finished_at = datetime.now()

    txt_output.write_text(proc.stdout + "\n" + proc.stderr, encoding="utf-8")
    if proc.returncode != 0:
        raise RuntimeError(f"Nmap failed with exit code {proc.returncode}. See {txt_output} for details.")
    if not xml_output.exists():
        raise RuntimeError("Nmap did not produce XML output; cannot continue to reporting.")

    return ScanRunResult(
        xml_output=xml_output,
        txt_output=txt_output,
        command=" ".join(cmd),
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=(finished_at - started_at).total_seconds(),
        return_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def parse_scan_xml(xml_path: Path) -> dict:
    root = ET.parse(xml_path).getroot()
    result = {"targets": [], "open_ports": [], "services": [], "scripts": [], "summary": {}}

    for host in root.findall("host"):
        addr = host.find("address")
        state = host.find("status")
        ip = addr.get("addr") if addr is not None else "unknown"
        host_state = state.get("state") if state is not None else "unknown"
        result["targets"].append({"target": ip, "state": host_state})

        ports_node = host.find("ports")
        if ports_node is None:
            continue

        for port in ports_node.findall("port"):
            p_state = port.find("state")
            if p_state is None or p_state.get("state") != "open":
                continue
            service = port.find("service")
            rec = {
                "target": ip,
                "protocol": port.get("protocol", ""),
                "port": port.get("portid", ""),
                "service": service.get("name", "unknown") if service is not None else "unknown",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            }
            result["open_ports"].append(rec)
            result["services"].append(f"{rec['service']}:{rec['port']}/{rec['protocol']}")

            for script in port.findall("script"):
                result["scripts"].append(
                    {
                        "target": ip,
                        "port": rec["port"],
                        "id": script.get("id", ""),
                        "output": script.get("output", ""),
                    }
                )

    result["summary"] = {
        "target_count": len(result["targets"]),
        "up_count": sum(1 for t in result["targets"] if t["state"] == "up"),
        "open_port_count": len(result["open_ports"]),
        "script_findings": len(result["scripts"]),
    }
    return result


def provider_payload(model: str, prompt_text: str) -> dict:
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": AI_SYSTEM_PROMPT},
            {"role": "user", "content": prompt_text},
        ],
        "temperature": 0.2,
        "max_tokens": 2400,
    }


def call_cerebras(api_key: str, model: str, prompt_text: str) -> str:
    if not api_key:
        raise ValueError("Missing Cerebras API key.")
    url = "https://api.cerebras.ai/v1/chat/completions"
    payload = provider_payload(model=model, prompt_text=prompt_text)
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    with httpx.Client(timeout=90.0) as client:
        response = client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
    return data["choices"][0]["message"]["content"]


def call_openrouter(api_key: str, model: str, prompt_text: str) -> str:
    if not api_key:
        raise ValueError("Missing OpenRouter API key.")
    url = "https://openrouter.ai/api/v1/chat/completions"
    payload = provider_payload(model=model or DEFAULT_OPENROUTER_MODEL, prompt_text=prompt_text)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-OpenRouter-Title": APP_NAME,
    }
    with httpx.Client(timeout=90.0) as client:
        response = client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
    return data["choices"][0]["message"]["content"]


def build_ai_prompt(
    scan_data: dict,
    target: str,
    profile_name: str,
    flags: str,
    raw_scan_output: str,
    xml_excerpt: str,
) -> str:
    return (
        "Generate a detailed professional security report from the evidence below. "
        "Use strict evidence-based reasoning and include severity rationale.\n\n"
        f"Target: {target}\n"
        f"Profile: {profile_name}\n"
        f"Nmap Flags: {flags}\n"
        f"Parsed Scan Data (JSON):\n{json.dumps(scan_data, indent=2)}\n\n"
        f"Raw Nmap Console Output:\n{raw_scan_output}\n\n"
        f"XML Excerpt:\n{xml_excerpt}"
    )


def generate_ai_report(
    scan_data: dict,
    target: str,
    profile_name: str,
    flags: str,
    cfg: AIConfig,
    raw_scan_output: str,
    xml_excerpt: str,
) -> tuple[str, str]:
    prompt_text = build_ai_prompt(
        scan_data=scan_data,
        target=target,
        profile_name=profile_name,
        flags=flags,
        raw_scan_output=raw_scan_output,
        xml_excerpt=xml_excerpt,
    )

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        progress.add_task("Generating AI report...", total=None)
        try:
            if cfg.provider == PROVIDER_CEREBRAS:
                report = call_cerebras(api_key=cfg.cerebras_api_key, model=cfg.model, prompt_text=prompt_text)
                return report, PROVIDER_CEREBRAS
            report = call_openrouter(api_key=cfg.openrouter_api_key, model=cfg.openrouter_model, prompt_text=prompt_text)
            return report, PROVIDER_OPENROUTER
        except Exception as first_error:
            if cfg.provider == PROVIDER_CEREBRAS and cfg.openrouter_api_key:
                report = call_openrouter(api_key=cfg.openrouter_api_key, model=cfg.openrouter_model, prompt_text=prompt_text)
                return report, PROVIDER_OPENROUTER
            raise RuntimeError(f"AI report generation failed: {first_error}") from first_error


def ensure_ai_configured(cfg: AIConfig) -> None:
    if cfg.provider == PROVIDER_CEREBRAS and not cfg.cerebras_api_key and not cfg.openrouter_api_key:
        raise RuntimeError("No AI key configured. Add CEREBRAS_API_KEY or OPENROUTER_API_KEY in .env or run configure-ai.")
    if cfg.provider == PROVIDER_OPENROUTER and not cfg.openrouter_api_key:
        raise RuntimeError("OPENROUTER_API_KEY is missing. Add it in .env or run configure-ai.")


def choose_provider_for_run(cfg: AIConfig) -> AIConfig:
    choice = numbered_choice(
        "Choose AI provider for this report",
        [
            f"Cerebras ({cfg.model})",
            f"OpenRouter ({cfg.openrouter_model})",
            "Use configured default",
        ],
        default=3,
    )
    if choice == 1:
        cfg.provider = PROVIDER_CEREBRAS
    elif choice == 2:
        cfg.provider = PROVIDER_OPENROUTER
    return cfg


def configure_ai() -> None:
    cfg = load_config()
    choice = numbered_choice("Choose default AI provider", ["Cerebras", "OpenRouter"], default=1)
    cfg.provider = PROVIDER_CEREBRAS if choice == 1 else PROVIDER_OPENROUTER
    cfg.model = Prompt.ask("Default Cerebras model", default=cfg.model or DEFAULT_CEREBRAS_MODEL)
    cfg.openrouter_model = Prompt.ask("Default OpenRouter model", default=cfg.openrouter_model or DEFAULT_OPENROUTER_MODEL)

    if Confirm.ask("Update Cerebras API key now?", default=not bool(cfg.cerebras_api_key)):
        cfg.cerebras_api_key = Prompt.ask("Cerebras API key", password=True)
    if Confirm.ask("Update OpenRouter API key now?", default=not bool(cfg.openrouter_api_key)):
        cfg.openrouter_api_key = Prompt.ask("OpenRouter API key", password=True)

    save_config(cfg)
    console.print("[green]Saved AI configuration.[/green]")


def save_reports(scan_data: dict, ai_report: Optional[str], provider_used: Optional[str], output_prefix: Path) -> None:
    parsed_path = output_prefix.with_name(output_prefix.name + "_parsed.json")
    parsed_path.write_text(json.dumps(scan_data, indent=2), encoding="utf-8")

    if ai_report:
        report_path = output_prefix.with_name(output_prefix.name + "_ai_report.md")
        header = (
            f"# {APP_NAME} AI Security Report\n\n"
            f"Generated: {datetime.now().isoformat()}\n\n"
            f"Provider: {provider_used}\n\n"
            f"Analyst: {DEVELOPER}\n\n"
        )
        report_path.write_text(header + ai_report, encoding="utf-8")
        console.print(f"[green]AI report saved:[/green] {report_path}")


def latest_report_file() -> Optional[Path]:
    if not OUTPUT_DIR.exists():
        return None
    files = sorted(OUTPUT_DIR.glob("*_ai_report.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def show_scan_process_details(result: ScanRunResult, target: str, flags: str, profile_name: str) -> None:
    table = Table(title="N-VIEW Scan Process")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Target", target)
    table.add_row("Profile", profile_name)
    table.add_row("Flags", flags)
    table.add_row("Command", result.command)
    table.add_row("Started", result.started_at.isoformat(timespec="seconds"))
    table.add_row("Finished", result.finished_at.isoformat(timespec="seconds"))
    table.add_row("Duration (s)", f"{result.duration_seconds:.2f}")
    table.add_row("Exit code", str(result.return_code))
    console.print(table)


def show_scan_summary(scan_data: dict) -> None:
    summary = scan_data["summary"]
    table = Table(title="N-VIEW Scan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Targets", str(summary["target_count"]))
    table.add_row("Targets Up", str(summary["up_count"]))
    table.add_row("Open Ports", str(summary["open_port_count"]))
    table.add_row("NSE Script Findings", str(summary["script_findings"]))
    console.print(table)


def show_detailed_scan_results(scan_data: dict) -> None:
    hosts = Table(title="Host States")
    hosts.add_column("Target", style="cyan")
    hosts.add_column("State", style="white")
    for host in scan_data.get("targets", []):
        hosts.add_row(str(host.get("target", "")), str(host.get("state", "")))
    console.print(hosts)

    ports = Table(title="Discovered Open Ports")
    ports.add_column("Target", style="cyan")
    ports.add_column("Port", style="white")
    ports.add_column("Protocol", style="white")
    ports.add_column("Service", style="white")
    ports.add_column("Product", style="white")
    ports.add_column("Version", style="white")
    open_ports = scan_data.get("open_ports", [])
    if not open_ports:
        ports.add_row("-", "-", "-", "No open ports found", "-", "-")
    else:
        for item in open_ports:
            ports.add_row(
                str(item.get("target", "")),
                str(item.get("port", "")),
                str(item.get("protocol", "")),
                str(item.get("service", "")),
                str(item.get("product", "")),
                str(item.get("version", "")),
            )
    console.print(ports)

    scripts = scan_data.get("scripts", [])
    if scripts:
        script_table = Table(title="NSE Script Results")
        script_table.add_column("Target", style="cyan")
        script_table.add_column("Port", style="white")
        script_table.add_column("Script ID", style="white")
        script_table.add_column("Output", style="white")
        for item in scripts:
            script_table.add_row(
                str(item.get("target", "")),
                str(item.get("port", "")),
                str(item.get("id", "")),
                str(item.get("output", ""))[:1200],
            )
        console.print(script_table)


def run_scan_pipeline(
    target: str,
    flags: str,
    profile_name: str,
    cfg: AIConfig,
    ask_for_ai: bool,
    generate_ai: bool = True,
    always_show_report: bool = True,
) -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = re.sub(r"[^a-zA-Z0-9_.-]+", "_", target)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_prefix = OUTPUT_DIR / f"{clean_target}_{timestamp}"

    console.print(f"\n[bold]Running:[/bold] nmap {flags} {target}")
    run_result = run_scan(target=target, flags=flags, output_prefix=output_prefix)
    scan_data = parse_scan_xml(run_result.xml_output)

    show_scan_process_details(run_result, target=target, flags=flags, profile_name=profile_name)
    show_scan_summary(scan_data)
    show_detailed_scan_results(scan_data)

    raw_scan_output = run_result.txt_output.read_text(encoding="utf-8", errors="ignore")[:10000] if run_result.txt_output.exists() else ""
    xml_excerpt = run_result.xml_output.read_text(encoding="utf-8", errors="ignore")[:12000] if run_result.xml_output.exists() else ""

    ai_report = None
    provider_used = None
    should_generate = generate_ai
    if ask_for_ai and generate_ai:
        should_generate = Confirm.ask("Generate full AI report now?", default=True)

    if should_generate:
        run_cfg = choose_provider_for_run(AIConfig.from_dict(cfg.to_dict()))
        ensure_ai_configured(run_cfg)
        ai_report, provider_used = generate_ai_report(
            scan_data=scan_data,
            target=target,
            profile_name=profile_name,
            flags=flags,
            cfg=run_cfg,
            raw_scan_output=raw_scan_output,
            xml_excerpt=xml_excerpt,
        )
        console.print("\n[bold green]AI report generated.[/bold green]")
        if always_show_report and ai_report:
            render_ai_report(ai_report, provider_used or run_cfg.provider)

    save_reports(scan_data=scan_data, ai_report=ai_report, provider_used=provider_used, output_prefix=output_prefix)
    console.print(f"[green]Raw XML saved:[/green] {run_result.xml_output}")


def scan_center_menu(cfg: AIConfig) -> None:
    while True:
        selection = numbered_choice(
            "Scan Center",
            [
                "Guided scan profiles",
                "Natural-language quick scan",
                "Custom raw Nmap flags",
                "Back",
            ],
            default=1,
        )
        if selection == 4:
            return

        target = Prompt.ask("Enter target (IP, CIDR, or host)")
        if selection == 1:
            flags, profile_name = choose_scan_profile()
        elif selection == 2:
            intent = Prompt.ask("Describe the scan intent")
            flags, profile_name = normalize_natural_language(intent)
        else:
            flags = Prompt.ask("Enter raw Nmap flags", default="-sV --top-ports 100 -T4")
            profile_name = "Custom"

        run_scan_pipeline(target=target, flags=flags, profile_name=profile_name, cfg=cfg, ask_for_ai=True, generate_ai=True)


def report_center_menu() -> None:
    while True:
        selection = numbered_choice(
            "Report Center",
            [
                "Show latest AI report in terminal",
                "List generated report files",
                "Back",
            ],
            default=1,
        )
        if selection == 3:
            return

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        if selection == 1:
            latest = latest_report_file()
            if not latest:
                console.print("[yellow]No AI reports found yet.[/yellow]")
                continue
            render_ai_report(latest.read_text(encoding="utf-8"), "from file")
            continue

        table = Table(title="Generated Reports")
        table.add_column("File", style="cyan")
        table.add_column("Updated", style="white")
        reports = sorted(OUTPUT_DIR.glob("*_ai_report.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not reports:
            console.print("[yellow]No report files available.[/yellow]")
            continue
        for file in reports[:20]:
            stamp = datetime.fromtimestamp(file.stat().st_mtime).isoformat(timespec="seconds")
            table.add_row(str(file.name), stamp)
        console.print(table)


def tools_menu() -> None:
    while True:
        selection = numbered_choice(
            "Tools & Diagnostics",
            [
                "Run health check (doctor)",
                "Run production bootstrap",
                "Show active .env path",
                "Back",
            ],
            default=1,
        )
        if selection == 4:
            return
        if selection == 1:
            doctor()
        elif selection == 2:
            bootstrap()
        else:
            console.print(f"[cyan]Using env file:[/cyan] {ENV_FILE}")


@app.command("menu")
def menu_mode() -> None:
    """Launch the fully interactive numbered menu experience."""
    cfg = load_config()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    while True:
        print_banner()
        console.print("\n[bold]Current AI setup[/bold]")
        console.print(f"Provider: {cfg.provider}")
        console.print(f"Cerebras model: {cfg.model}")
        console.print(f"OpenRouter model: {cfg.openrouter_model}")
        console.print(f"Cerebras key: {mask_secret(cfg.cerebras_api_key)}")
        console.print(f"OpenRouter key: {mask_secret(cfg.openrouter_api_key)}")

        action = numbered_choice(
            "Main Menu",
            [
                "Scan Center",
                "Report Center",
                "AI Provider Settings",
                "Tools & Diagnostics",
                "Exit",
            ],
            default=1,
        )

        if action == 1:
            scan_center_menu(cfg)
        elif action == 2:
            report_center_menu()
        elif action == 3:
            configure_ai()
            cfg = load_config()
        elif action == 4:
            tools_menu()
        else:
            console.print("[yellow]Goodbye from N-VIEW.[/yellow]")
            return


@app.command("scan")
def scan_non_interactive(
    target: str = typer.Option(..., "--target", "-t", help="Target host, IP, or CIDR."),
    natural_language: Optional[str] = typer.Option(None, "--nl", help="Describe desired scan in natural language and N-VIEW will normalize to flags."),
    flags: Optional[str] = typer.Option(None, "--flags", "-f", help="Explicit nmap flags."),
    ai: bool = typer.Option(True, "--ai/--no-ai", help="Generate AI report after scan."),
    show_report: bool = typer.Option(True, "--show-report/--no-show-report", help="Render generated AI report in terminal."),
) -> None:
    """Run scan directly from CLI while keeping N-VIEW normalization and reporting."""
    print_banner()
    cfg = load_config()

    if flags:
        selected_flags = flags
        profile_name = "Custom"
    else:
        selected_flags, profile_name = normalize_natural_language(natural_language or "quick scan")

    run_scan_pipeline(
        target=target,
        flags=selected_flags,
        profile_name=profile_name,
        cfg=cfg,
        ask_for_ai=False,
        generate_ai=ai,
        always_show_report=show_report,
    )
    console.print("[bold cyan]Done.[/bold cyan]")


@app.command("configure-ai")
def configure_ai_command() -> None:
    """Configure AI provider, preferred models, and API keys."""
    print_banner()
    configure_ai()


@app.command("version")
def version() -> None:
    """Show current N-VIEW version."""
    print_banner()


@app.command("doctor")
def doctor() -> None:
    """Validate runtime prerequisites and provider setup."""
    print_banner()
    cfg = load_config()
    deps = check_dependencies(auto_fix=False)

    table = Table(title="N-VIEW Health Check")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Details", style="white")

    platform_label = deps["os"]
    if deps["distro"] != "n/a":
        platform_label = f"{platform_label} ({deps['distro']})"

    table.add_row("Detected platform", "OK", platform_label)
    table.add_row(
        "Nmap availability",
        deps["nmap_status"],
        deps["nmap_path"] if deps["nmap_status"] == "OK" else "Install Nmap or add it to PATH",
    )
    table.add_row("Cerebras key", "SET" if bool(cfg.cerebras_api_key) else "MISSING", mask_secret(cfg.cerebras_api_key))
    table.add_row("OpenRouter key", "SET" if bool(cfg.openrouter_api_key) else "MISSING", mask_secret(cfg.openrouter_api_key))
    table.add_row("Default provider", "OK", cfg.provider)
    table.add_row("Cerebras model", "OK", cfg.model)
    table.add_row("OpenRouter model", "OK", cfg.openrouter_model)
    console.print(table)

    if deps["nmap_status"] == "MISSING":
        console.print("\n[bold yellow]Manual Nmap install options:[/bold yellow]")
        for cmd in deps["manual_install"]:
            console.print(f"[yellow]- {cmd}[/yellow]")


@app.command("bootstrap")
def bootstrap(
    fix_dependencies: bool = typer.Option(True, "--fix-dependencies/--no-fix-dependencies", help="Attempt to auto-install missing dependencies."),
    install_aliases: bool = typer.Option(True, "--install-aliases/--no-install-aliases", help="Create nview and n-view command launchers."),
) -> None:
    """Prepare runtime for production use: dependency checks + command aliases."""
    print_banner()
    deps = check_dependencies(auto_fix=fix_dependencies)

    table = Table(title="N-VIEW Bootstrap")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Details", style="white")

    platform_label = deps["os"]
    if deps["distro"] != "n/a":
        platform_label = f"{platform_label} ({deps['distro']})"
    table.add_row("Detected platform", "OK", platform_label)
    table.add_row("Nmap", deps["nmap_status"], deps["nmap_path"])

    created: list[str] = []
    notes: list[str] = []
    if install_aliases:
        created, notes = install_command_aliases()
        table.add_row("Command aliases", "OK", "Created launchers for nview and n-view")
    else:
        table.add_row("Command aliases", "SKIPPED", "Launchers were not created")

    console.print(table)

    if created:
        console.print("\n[green]Created launcher files:[/green]")
        for item in created:
            console.print(f"[green]- {item}[/green]")

    if deps["nmap_status"] != "OK":
        console.print("\n[bold yellow]Automatic Nmap install did not complete. Install manually:[/bold yellow]")
        for cmd in deps["manual_install"]:
            console.print(f"[yellow]- {cmd}[/yellow]")

    if notes:
        console.print("\n[bold cyan]Post-setup notes:[/bold cyan]")
        for note in notes:
            console.print(f"[cyan]- {note}[/cyan]")


def entry() -> None:
    if len(sys.argv) == 1:
        sys.argv.append("menu")
    app()


if __name__ == "__main__":
    entry()
