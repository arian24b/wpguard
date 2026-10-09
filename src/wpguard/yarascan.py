"""YARA support through the `yara` (or YARA-X `yr`) command line; no Python dependency."""

import shutil
import subprocess
from pathlib import Path


def tool() -> list[str] | None:
    if exe := shutil.which("yara"):
        return [exe, "-r", "-w"]
    if exe := shutil.which("yr"):
        return [exe, "scan", "-r"]
    return None


def scan(rules: Path, target: Path, timeout: int = 900) -> tuple[dict[str, list[str]], str]:
    """Run one rule file over `target`. Returns ({path: [rule names]}, error text)."""
    base = tool()
    if base is None:
        return {}, "yara not found (install `yara` or YARA-X `yr`)"
    try:
        r = subprocess.run(
            [*base, str(rules), str(target)], capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return {}, f"timeout after {timeout}s"
    hits: dict[str, list[str]] = {}
    for line in r.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and not parts[0].startswith("0x"):
            hits.setdefault(parts[1].strip(), []).append(parts[0])
    return hits, r.stderr.strip().splitlines()[-1] if r.returncode and r.stderr.strip() else ""
