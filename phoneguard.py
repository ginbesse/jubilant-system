#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HOME = Path.home()
GUARD_DIR = HOME / ".phoneguard"
LOG_FILE = GUARD_DIR / "phoneguard.log"
ALERT_LOG = GUARD_DIR / "alerts.log"
REPORT_FILE = GUARD_DIR / "security_report.json"
CONFIG_FILE = GUARD_DIR / "guard_config.json"
BASELINE_FILE = GUARD_DIR / "baseline.json"
RISKY_TOKENS = ["nc ", "ncat", "socat", "chmod 777", "sshpass", "curl ", "wget ", "telnet", "dropbear", "metasploit", "ngrok"]
SUSPICIOUS_PORTS = {"22", "23", "4444", "5555", "9999", "1337", "4445"}


def run(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT).strip()
    except subprocess.CalledProcessError as exc:
        return (exc.output or "").strip()


def ensure_dirs() -> None:
    GUARD_DIR.mkdir(exist_ok=True)


def log(message: str) -> None:
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    print(line)
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def write_alert(message: str) -> None:
    with ALERT_LOG.open("a", encoding="utf-8") as handle:
        handle.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def secure_permissions() -> None:
    try:
        os.chmod(GUARD_DIR, 0o700)
    except OSError:
        pass

    ssh_dir = HOME / ".ssh"
    if ssh_dir.exists():
        try:
            os.chmod(ssh_dir, 0o700)
        except OSError:
            pass

    for history_file in [HOME / ".bash_history", HOME / ".zsh_history"]:
        if history_file.exists():
            try:
                os.chmod(history_file, 0o600)
            except OSError:
                pass


def hash_file(path: Path) -> str:
    if not path.exists():
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_config() -> dict[str, Any]:
    config = load_json(CONFIG_FILE, None)
    if isinstance(config, dict):
        return config
    return {"watch_interval": 30, "alert_on_suspicious": True, "auto_block": True}


def save_config(config: dict[str, Any]) -> None:
    save_json(CONFIG_FILE, config)


def collect_state() -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "user": run("whoami"),
        "processes": run("ps -A | head -n 20"),
        "interfaces": run("ip -o addr show 2>/dev/null | head -n 20"),
        "dns": run("getprop net.dns1 2>/dev/null"),
        "termux_root": str((Path("/data/data/com.termux")).exists()),
        "boot_dir_exists": str((HOME / ".termux" / "boot").exists()),
        "packages": run("pkg list-installed 2>/dev/null | head -n 20"),
        "ports": run("ss -lnt 2>/dev/null | head -n 20"),
    }


def contains_risky_patterns(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in RISKY_TOKENS)


def inspect_suspicious_artifacts() -> list[str]:
    findings = []
    history_files = [HOME / ".bash_history", HOME / ".zsh_history", HOME / ".profile", HOME / ".bashrc", HOME / ".zshrc"]
    for path in history_files:
        if path.exists():
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if contains_risky_patterns(content):
                findings.append(f"suspicious shell content in {path.name}")

    if (HOME / ".ssh").exists():
        findings.append("SSH directory exists; verify its contents")

    for suspicious_path in [HOME / "tmp", HOME / ".cache"]:
        if suspicious_path.exists() and suspicious_path.is_dir():
            findings.append(f"temporary area exists: {suspicious_path}")

    return findings


def inspect_processes() -> list[str]:
    output = run("ps -A")
    findings = []
    if not output:
        return findings
    lowered = output.lower()
    for token in ["nc", "ncat", "socat", "dropbear", "telnet", "ngrok", "metasploit"]:
        if token in lowered:
            findings.append(f"suspicious process mention: {token}")
    return findings


def inspect_network() -> list[str]:
    findings = []
    ports_output = ""
    if shutil.which("ss"):
        ports_output = run("ss -lnt 2>/dev/null")
    elif shutil.which("netstat"):
        ports_output = run("netstat -an 2>/dev/null")

    if not ports_output:
        return findings

    for port in SUSPICIOUS_PORTS:
        if port in ports_output:
            findings.append(f"suspicious listening port detected: {port}")
    return findings


def inspect_tampering() -> list[str]:
    findings = []
    baseline = load_json(BASELINE_FILE, {})
    if not isinstance(baseline, dict):
        baseline = {}

    targets = [
        Path(__file__),
        CONFIG_FILE,
        HOME / ".termux" / "boot" / "phoneguard",
    ]
    current_snapshot = {}
    for target in targets:
        current_snapshot[str(target)] = hash_file(target)

    if baseline:
        for target_path, current_hash in current_snapshot.items():
            previous_hash = baseline.get(target_path)
            if previous_hash and previous_hash != current_hash:
                findings.append(f"tamper detected: {Path(target_path).name}")
    else:
        save_json(BASELINE_FILE, current_snapshot)
    return findings


def attempt_auto_block(findings: list[str], config: dict[str, Any]) -> None:
    if not config.get("auto_block", True):
        return
    if not shutil.which("iptables"):
        log("iptables not available; skipping automatic blocking")
        return

    if run("id -u") != "0":
        log("Not running as root; skipping automatic blocking")
        return

    ports = [port for port in SUSPICIOUS_PORTS if any(f"{port}" in finding for finding in findings)]
    for port in ports:
        for proto in ["tcp", "udp"]:
            cmd = f"iptables -A OUTPUT -p {proto} --dport {port} -j DROP"
            result = run(cmd)
            if result:
                log(f"Automatic block attempted for {proto}/{port}: {result}")
            else:
                log(f"Automatic block applied for {proto}/{port}")


def score_findings(findings: list[str]) -> int:
    score = 0
    for finding in findings:
        if "tamper" in finding.lower():
            score += 45
        elif "suspicious listening port" in finding.lower():
            score += 35
        elif "suspicious process" in finding.lower():
            score += 35
        elif "suspicious shell" in finding.lower():
            score += 25
        else:
            score += 15
    return min(score, 100)


def risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def build_report(findings: list[str], state: dict[str, Any]) -> dict[str, Any]:
    device_id = hashlib.sha256(str(HOME).encode("utf-8")).hexdigest()[:12]
    score = score_findings(findings)
    return {
        "device_id": device_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": state.get("platform", "unknown"),
        "user": state.get("user", "unknown"),
        "findings": findings,
        "finding_count": len(findings),
        "risk_score": score,
        "risk_level": risk_level(score),
        "boot_dir_exists": state.get("boot_dir_exists", False),
        "termux_root": state.get("termux_root", False),
        "launcher_hash": hash_file(HOME / ".termux" / "boot" / "phoneguard"),
    }


def write_report(findings: list[str], state: dict[str, Any]) -> None:
    report = build_report(findings, state)
    with REPORT_FILE.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    log(f"Anonymized security report written to {REPORT_FILE}")


def export_artifacts() -> None:
    export_dir = GUARD_DIR / "exports"
    export_dir.mkdir(exist_ok=True)
    for source in [REPORT_FILE, LOG_FILE, ALERT_LOG]:
        if source.exists():
            shutil.copy2(source, export_dir / source.name)
    log(f"Artifacts exported to {export_dir}")


def apply_hardening() -> None:
    ensure_dirs()
    secure_permissions()
    boot_dir = HOME / ".termux" / "boot"
    boot_dir.mkdir(parents=True, exist_ok=True)
    launcher = boot_dir / "phoneguard"
    launcher.write_text(
        "#!/data/data/com.termux/files/usr/bin/bash\n"
        f'python "{GUARD_DIR / "phoneguard.py"}" --once\n',
        encoding="utf-8",
    )
    os.chmod(launcher, 0o755)

    config = {"watch_interval": 30, "alert_on_suspicious": True, "auto_block": True}
    save_config(config)
    save_json(BASELINE_FILE, {
        str(Path(__file__)): hash_file(Path(__file__)),
        str(CONFIG_FILE): hash_file(CONFIG_FILE),
        str(HOME / ".termux" / "boot" / "phoneguard"): hash_file(HOME / ".termux" / "boot" / "phoneguard"),
    })
    log("Hardening applied; startup monitor installed and baseline saved")


def run_scan() -> list[str]:
    log("Starting PhoneGuard security scan")
    state = collect_state()
    log(f"Platform: {state['platform']}")
    log(f"User: {state['user']}")

    config = load_config()
    findings = inspect_suspicious_artifacts() + inspect_processes() + inspect_network() + inspect_tampering()
    if findings:
        for finding in findings:
            log(f"ALERT: {finding}")
            write_alert(finding)
        attempt_auto_block(findings, config)
    else:
        log("No obvious suspicious artifacts were found")

    write_report(findings, state)
    return findings


def show_status() -> None:
    if REPORT_FILE.exists():
        report = load_json(REPORT_FILE, {})
        if isinstance(report, dict):
            log(f"Status: risk_level={report.get('risk_level', 'unknown')} risk_score={report.get('risk_score', 0)} findings={report.get('finding_count', 0)}")
            return
    log("Status: no report available yet")


def reset_guard() -> None:
    for path in [LOG_FILE, ALERT_LOG, REPORT_FILE, BASELINE_FILE, CONFIG_FILE]:
        if path.exists():
            path.unlink()
    log("Guard state reset")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PhoneGuard for Termux")
    parser.add_argument("--apply", action="store_true", help="install startup hardening")
    parser.add_argument("--once", action="store_true", help="run one scan")
    parser.add_argument("--watch", action="store_true", help="run continuous monitoring")
    parser.add_argument("--status", action="store_true", help="show latest security status")
    parser.add_argument("--export", action="store_true", help="export logs and reports")
    parser.add_argument("--reset", action="store_true", help="reset guard state")
    return parser.parse_args()


def main() -> int:
    ensure_dirs()
    args = parse_args()

    if args.apply:
        apply_hardening()
        return 0

    if args.reset:
        reset_guard()
        return 0

    if args.export:
        export_artifacts()
        return 0

    if args.status:
        show_status()
        return 0

    findings = run_scan()

    if args.watch:
        config = load_config()
        interval = int(config.get("watch_interval", 30))
        log(f"Watch mode enabled with {interval}s interval")
        while True:
            time.sleep(interval)
            run_scan()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
