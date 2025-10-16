#!/usr/bin/env python3
"""Utility helpers to downgrade Dependabot updates when CI fails.

The script inspects the current branch and compares it with the provided base
reference to understand which dependencies were updated by Dependabot. When a
supported dependency is found, it rewrites the working tree with a downgraded
version that moves one step closer to the base version. A summary of the action
is exported through the GitHub Actions output file when available.

This module intentionally focuses on a small set of primitives so that projects
can swap in custom detectors without changing the workflow orchestration. The
current implementation recognises Python requirement pins and Docker base
images, but the architecture keeps the parsing logic pluggable.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


class DependencyUpdateError(RuntimeError):
    """Raised when the downgrade process encounters an unrecoverable error."""


@dataclasses.dataclass
class DependencyUpdate:
    """Represents a single dependency change."""

    file_path: Path
    name: str
    current_version: str
    target_version: str
    base_version: str
    kind: str
    metadata: Dict[str, str]

    def is_exhausted(self) -> bool:
        """Return True when the current version is already at the base version."""

        return compare_versions(self.current_version, self.base_version) <= 0

    def next_candidate(self) -> Optional[str]:
        """Compute the next downgrade candidate, if any."""

        if self.is_exhausted():
            return None

        candidate = decrement_version(self.current_version)
        if candidate is None:
            return None

        # Do not go below the base version.
        if compare_versions(candidate, self.base_version) < 0:
            return self.base_version

        return candidate

    def apply(self, candidate: str) -> None:
        """Rewrite the dependency file with the candidate version."""

        if self.kind == "requirements":
            _rewrite_requirement_pin(self.file_path, self.name, self.current_version, candidate)
        elif self.kind == "docker-base-image":
            _rewrite_docker_base(self.file_path, candidate, self.metadata)
        else:
            raise DependencyUpdateError(f"Unsupported dependency kind: {self.kind}")

        self.current_version = candidate


def compare_versions(version_a: str, version_b: str) -> int:
    """Compare two dotted version strings numerically."""

    seq_a = _normalise_version(version_a)
    seq_b = _normalise_version(version_b)
    return (seq_a > seq_b) - (seq_a < seq_b)


def _normalise_version(version: str) -> Tuple[int, ...]:
    tokens = re.findall(r"\d+", version)
    if not tokens:
        return (0,)
    return tuple(int(token) for token in tokens)


def decrement_version(version: str) -> Optional[str]:
    """Return the previous semantic version by decrementing the last component."""

    tokens = re.split(r"[.]+", version)
    numeric = []
    for token in tokens:
        if token.isdigit():
            numeric.append(int(token))
        else:
            return None

    if not numeric:
        return None

    for index in range(len(numeric) - 1, -1, -1):
        if numeric[index] > 0:
            numeric[index] -= 1
            for reset in range(index + 1, len(numeric)):
                numeric[reset] = 0
            return ".".join(str(value) for value in numeric)
    return None


def _rewrite_requirement_pin(path: Path, package: str, old: str, new: str) -> None:
    pattern = re.compile(rf"^(\s*{re.escape(package)}\s*==\s*){re.escape(old)}(\s*(?:#.*)?)$")
    lines = path.read_text().splitlines()
    updated: List[str] = []
    replaced = False

    for line in lines:
        match = pattern.match(line)
        if match:
            updated.append(f"{match.group(1)}{new}{match.group(2)}")
            replaced = True
        else:
            updated.append(line)

    if not replaced:
        raise DependencyUpdateError(f"Failed to update {package} in {path}")

    path.write_text("\n".join(updated) + "\n")


def _rewrite_docker_base(path: Path, candidate: str, metadata: Dict[str, str]) -> None:
    tag_suffix = metadata.get("tag_suffix", "")
    pattern = re.compile(rf"^(FROM\s+{re.escape(metadata['image'])}:)(\S+)")
    lines = path.read_text().splitlines()
    updated: List[str] = []
    replaced = False

    for line in lines:
        match = pattern.match(line)
        if match:
            updated.append(f"{match.group(1)}{candidate}{tag_suffix}")
            replaced = True
        else:
            updated.append(line)

    if not replaced:
        raise DependencyUpdateError(f"Failed to update base image in {path}")

    path.write_text("\n".join(updated) + "\n")


def run_git_command(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def load_file_from_ref(ref: str, path: Path) -> str:
    return run_git_command("show", f"{ref}:{path.as_posix()}")


def detect_updates(base_ref: str, workspace: Path) -> List[DependencyUpdate]:
    changed_files = run_git_command("diff", "--name-only", base_ref).splitlines()
    updates: List[DependencyUpdate] = []

    for relative in changed_files:
        file_path = workspace / relative
        if not file_path.exists():
            continue

        if file_path.name == "requirements.txt":
            updates.extend(_detect_requirement_updates(file_path, base_ref))
        elif file_path.name.lower() == "dockerfile":
            maybe = _detect_docker_base_update(file_path, base_ref)
            if maybe:
                updates.append(maybe)

    return updates


def _detect_requirement_updates(path: Path, base_ref: str) -> Iterable[DependencyUpdate]:
    try:
        base_text = load_file_from_ref(base_ref, path)
    except subprocess.CalledProcessError:
        return []

    base_versions = _parse_requirements(base_text)
    head_versions = _parse_requirements(path.read_text())

    for package, head_version in head_versions.items():
        base_version = base_versions.get(package)
        if base_version and compare_versions(head_version, base_version) > 0:
            yield DependencyUpdate(
                file_path=path,
                name=package,
                current_version=head_version,
                target_version=head_version,
                base_version=base_version,
                kind="requirements",
                metadata={},
            )


def _parse_requirements(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            package, version = line.split("==", 1)
            result[package.strip()] = version.strip()
    return result


def _detect_docker_base_update(path: Path, base_ref: str) -> Optional[DependencyUpdate]:
    try:
        base_text = load_file_from_ref(base_ref, path)
    except subprocess.CalledProcessError:
        return None

    head_text = path.read_text()

    base_match = re.search(r"^FROM\s+(\S+):(\S+)$", base_text, re.MULTILINE)
    head_match = re.search(r"^FROM\s+(\S+):(\S+)$", head_text, re.MULTILINE)
    if not base_match or not head_match:
        return None

    base_image, base_tag = base_match.groups()
    head_image, head_tag = head_match.groups()

    if base_image != head_image:
        return None

    base_version = _extract_numeric_version(base_tag)
    head_version = _extract_numeric_version(head_tag)
    if not base_version or not head_version:
        return None

    if compare_versions(head_version, base_version) <= 0:
        return None

    suffix = head_tag.replace(head_version, "", 1)

    return DependencyUpdate(
        file_path=path,
        name=base_image,
        current_version=head_version,
        target_version=head_version,
        base_version=base_version,
        kind="docker-base-image",
        metadata={"image": base_image, "tag_suffix": suffix},
    )


def _extract_numeric_version(tag: str) -> Optional[str]:
    match = re.search(r"\d+(?:\.\d+)*", tag)
    return match.group(0) if match else None


def write_outputs(outputs: Dict[str, str], output_path: Optional[str]) -> None:
    if output_path:
        with open(output_path, "a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                handle.write(f"{key}={value}\n")


def downgrade(base_ref: str, workspace: Path, output_path: Optional[str]) -> int:
    updates = detect_updates(base_ref, workspace)
    if not updates:
        diff_stat = run_git_command("diff", "--stat", base_ref)
        status = "exhausted" if not diff_stat else "skipped"
        write_outputs({"status": status}, output_path)
        return 0

    for update in updates:
        candidate = update.next_candidate()
        if not candidate:
            continue

        update.apply(candidate)
        write_outputs(
            {
                "status": "modified",
                "file": str(update.file_path),
                "dependency": update.name,
                "new_version": candidate,
                "base_version": update.base_version,
            },
            output_path,
        )
        return 0

    write_outputs({"status": "exhausted"}, output_path)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Dependabot downgrade helper")
    sub = parser.add_subparsers(dest="command", required=True)

    downgrade_parser = sub.add_parser("downgrade", help="Downgrade a dependency by one step")
    downgrade_parser.add_argument("--base-ref", required=True, help="Git reference for the base branch")
    downgrade_parser.add_argument("--output", help="Path to the GitHub Actions output file")

    args = parser.parse_args(argv)
    workspace = Path.cwd()

    if args.command == "downgrade":
        return downgrade(args.base_ref, workspace, args.output)

    raise AssertionError("Unhandled command")


if __name__ == "__main__":
    sys.exit(main())
