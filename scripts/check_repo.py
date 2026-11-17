#!/usr/bin/env python3
"""Local repository hygiene check for the public RustMP workspace.

No network traffic or third-party dependencies. Run from any directory:
    python scripts/check_repo.py
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "ARCHITECTURE.md",
    "PORTING_PLAN.md",
    "TRACE_ANALYSIS.md",
    ".github/workflows/rust.yml",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/pull_request_template.md",
    "Cargo.toml",
    "Cargo.lock",
    "config.json",
)
PACKAGES = ("rustmp-core", "rustmp-protocol", "rustmp-server", "rustmp-transport")


def check() -> list[str]:
    errors: list[str] = []
    for item in REQUIRED:
        if not (ROOT / item).is_file():
            errors.append(f"Обязательный файл отсутствует: {item}")

    try:
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        version = workspace["workspace"]["package"]["version"]
        locked = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
        existing = {entry["name"]: entry["version"] for entry in locked["package"]}
        for package in PACKAGES:
            if existing.get(package) != version:
                errors.append(f"Cargo.lock: {package} не совпадает с версией {version}")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        if version not in readme:
            errors.append(f"README.md: текущая версия {version} не указана")
    except (KeyError, OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"Ошибка версии Cargo workspace: {exc}")

    try:
        config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
        if config["network"]["bind"] != "127.0.0.1":
            errors.append("config.json: небезопасный адрес bind для прототипа")
        if config.get("password"):
            errors.append("config.json: не публикуйте настоящий пароль в репозитории")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"Ошибка config.json: {exc}")

    try:
        raw = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z"])
        tracked = [Path(p.decode("utf-8")) for p in raw.split(b"\0") if p]
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        errors.append(f"Не удалось получить список файлов Git: {exc}")
        tracked = []

    for rel in tracked:
        path = rel.as_posix()
        parts = rel.parts
        if (
            rel.suffix.lower() in {".pcap", ".pcapng", ".cap", ".exe", ".dll"}
            or ".env" in parts
            or any(part in {"target", ".idea", ".vscode", "node_modules"} for part in parts)
            or path.endswith(".log")
        ):
            errors.append(f"В Git отслеживается лишний или приватный файл: {path}")

    docs = [ROOT / path for path in tracked if path.suffix.lower() == ".md"]
    link_pattern = re.compile(r"!?\[[^\]]*]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
    html_anchors = re.compile(r'href=["\']#([^"\']+)["\']')
    for doc in docs:
        content = doc.read_text(encoding="utf-8")
        headings = re.findall(r"(?m)^#{1,6}\s+(.+?)\s*$", content)
        slugs = {
            re.sub(r"[^\w\s-]", "", h.lower(), flags=re.UNICODE)
            .strip().replace(" ", "-")
            for h in headings
        }
        for anchor in html_anchors.findall(content):
            if unquote(anchor) not in slugs:
                errors.append(f"{doc.relative_to(ROOT)}: нет заголовка для #{anchor}")
        for target in link_pattern.findall(content):
            if target.startswith(("https://", "http://", "mailto:", "data:")):
                continue
            parsed = urlsplit(target)
            if parsed.scheme:
                continue
            name = unquote(parsed.path)
            if not name or name.startswith("#"):
                continue
            resolved = (doc.parent / name).resolve()
            if not resolved.is_relative_to(ROOT) or not resolved.exists():
                errors.append(
                    f"{doc.relative_to(ROOT)}: не найдена локальная ссылка {target}"
                )
    return errors


def main() -> int:
    # Windows GitHub Actions can default to cp1252 even for UTF-8 files.
    # Use UTF-8 for diagnostic messages on every supported platform.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    errors = check()
    if errors:
        print(f"[FAIL] Найдено проблем: {len(errors)}", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1
    print("[OK] Версии, конфигурация, внутренние ссылки и Git-файлы проверены.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
