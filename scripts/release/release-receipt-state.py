#!/usr/bin/env python3
"""Immutable, once-per-SHA release receipt state machine."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import re
import socket
import sys
from typing import Any


TERMINAL_STATUSES = {"passed", "failed", "blocked", "aborted"}
VERDICT_STATUSES = TERMINAL_STATUSES | {"not-run"}
COMPONENT_KINDS = (
    "build",
    "cmdlet",
    "windows",
    "coverage",
    "persistence",
    "security",
    "orchestration",
)


class ReceiptError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: pathlib.Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ReceiptError(f"Refusing symlinked receipt: {path}")
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError(f"Cannot read valid receipt {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReceiptError(f"Receipt must contain a JSON object: {path}")
    return value


def sha256_file(path: pathlib.Path) -> str:
    if path.is_symlink():
        raise ReceiptError(f"Refusing symlinked receipt: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_exclusive(path: pathlib.Path, value: dict[str, Any]) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except FileExistsError as exc:
        raise ReceiptError(f"Refusing to overwrite immutable receipt: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def validate_sha(value: str) -> str:
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise ReceiptError("Candidate SHA must be exactly 40 lowercase hexadecimal characters")
    return value


def ensure_root_matches(root: pathlib.Path, sha: str) -> None:
    if root.name != sha:
        raise ReceiptError("Release receipt directory must be named for the exact candidate SHA")


def validate_coverage_source(value: dict[str, Any], claim_value: dict[str, Any], sha: str) -> None:
    """Fail closed on incoherent evidence presented as passing native coverage."""
    tree = claim_value.get("candidateTree")
    if value.get("candidateSha") != sha or value.get("candidateTree") != tree:
        raise ReceiptError("Coverage receipt is not bound to the exact candidate SHA and tree")
    if value.get("status") != "passed":
        return
    coverage = value.get("coverage")
    if not isinstance(coverage, dict) or coverage.get("status") != "passed":
        raise ReceiptError("Passing coverage component has no passing coverage summary")
    if coverage.get("candidateSha") != sha or coverage.get("candidateTree") != tree:
        raise ReceiptError("Coverage summary is not bound to the exact candidate SHA and tree")
    if coverage.get("invocationCount") != 1 or isinstance(
        coverage.get("invocationCount"), bool
    ):
        raise ReceiptError("Passing coverage must contain exactly one invocation")
    test_count = coverage.get("testCount")
    if not isinstance(test_count, int) or isinstance(test_count, bool) or test_count <= 0:
        raise ReceiptError("Passing coverage must contain at least one test")
    minimum = coverage.get("minimum")
    if (
        not isinstance(minimum, (int, float))
        or isinstance(minimum, bool)
        or not math.isfinite(minimum)
        or minimum < 90
        or minimum > 100
    ):
        raise ReceiptError("Passing coverage minimum must be between 90 and 100")
    metrics = coverage.get("metrics")
    required_metrics = {"statements", "lines", "functions"}
    if not isinstance(metrics, dict) or set(metrics) != required_metrics:
        raise ReceiptError("Coverage metrics must be exactly statements, lines, and functions")
    for name in sorted(required_metrics):
        metric = metrics[name]
        if not isinstance(metric, dict):
            raise ReceiptError(f"Coverage metric {name} must be an object")
        covered = metric.get("covered")
        total = metric.get("total")
        if (
            not isinstance(covered, int)
            or isinstance(covered, bool)
            or not isinstance(total, int)
            or isinstance(total, bool)
            or total <= 0
            or covered < 0
            or covered > total
        ):
            raise ReceiptError(f"Coverage metric {name} has invalid counts")
        if covered * 100 < minimum * total:
            raise ReceiptError(f"Coverage metric {name} is below the exact threshold")
    inventory = coverage.get("sourceInventory")
    source_file_count = coverage.get("sourceFileCount")
    if (
        not isinstance(inventory, list)
        or not inventory
        or not isinstance(source_file_count, int)
        or isinstance(source_file_count, bool)
        or source_file_count != len(inventory)
    ):
        raise ReceiptError("Coverage source inventory count is incoherent")
    normalized_inventory: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for item in inventory:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ReceiptError("Coverage source inventory entries must contain path and sha256")
        path = item.get("path")
        digest = item.get("sha256")
        if (
            not isinstance(path, str)
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", path)
            or path.startswith("/")
            or path.startswith("./")
            or path.endswith("/")
            or "//" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or path in seen_paths
        ):
            raise ReceiptError("Coverage source inventory contains an unsafe or duplicate path")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ReceiptError("Coverage source inventory contains an invalid SHA-256")
        seen_paths.add(path)
        normalized_inventory.append({"path": path, "sha256": digest})
    encoded_inventory = json.dumps(
        normalized_inventory, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    expected_source_hash = hashlib.sha256(encoded_inventory).hexdigest()
    source_hash = coverage.get("sourceHash")
    if (
        not isinstance(source_hash, str)
        or not re.fullmatch(r"[a-f0-9]{64}", source_hash)
        or source_hash != expected_source_hash
    ):
        raise ReceiptError("Coverage source hash does not match its ordered inventory")


def discover_coverage_inventory(source_root: pathlib.Path) -> list[dict[str, str]]:
    if source_root.is_symlink() or not source_root.is_dir():
        raise ReceiptError("Coverage source root is missing or unsafe")
    source_root = source_root.resolve(strict=True)
    inventory: list[dict[str, str]] = []
    for relative_root in (
        pathlib.Path("src/HostHunterNextGeneration"),
        pathlib.Path("client/HostHunter.Client"),
    ):
        owned_root = source_root / relative_root
        if owned_root.is_symlink() or not owned_root.is_dir():
            raise ReceiptError(f"Coverage-owned source root is missing or unsafe: {relative_root}")
        for path in owned_root.rglob("*"):
            if (
                path.suffix.lower() not in {".ps1", ".psm1"}
                or path.is_symlink()
                or not path.is_file()
            ):
                continue
            relative_path = path.relative_to(source_root).as_posix()
            inventory.append({"path": relative_path, "sha256": sha256_file(path)})
    return sorted(inventory, key=lambda item: item["path"])


def verdict_summary(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {"status": "not-run", "receipt": None}
    status = value.get("status")
    if status not in VERDICT_STATUSES:
        raise ReceiptError(f"Invalid component verdict status: {status!r}")
    result: dict[str, Any] = {"status": status}
    for key in (
        "candidateSha", "startedAtUtc", "finishedAtUtc", "reason", "rowCount",
        "controllerImageId", "candidateTree", "images", "phases", "coverage",
        "retryCount", "buildCount", "failedPhase",
    ):
        if key in value:
            result[key] = value[key]
    return result


def claim(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root)
    sha = validate_sha(args.sha)
    ensure_root_matches(root, sha)
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
    except FileExistsError as exc:
        raise ReceiptError(f"Exact SHA has already been claimed and can never rerun: {sha}") from exc
    value = {
        "schemaVersion": 1,
        "state": "running",
        "attempt": 1,
        "retryCount": 0,
        "candidateSha": sha,
        "candidateTree": args.tree,
        "startedAtUtc": args.started,
        "owner": {"host": socket.gethostname(), "pid": args.pid},
    }
    write_exclusive(root / "claim.json", value)
    print(root / "claim.json")
    return 0


def record(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root)
    sha = validate_sha(args.sha)
    ensure_root_matches(root, sha)
    claim_value = load_json(root / "claim.json")
    if (root / "receipt.json").exists():
        raise ReceiptError("Cannot add a component verdict after terminal sealing")
    destination = root / f"{args.kind}-receipt.json"
    if args.source:
        source = pathlib.Path(args.source)
        if source.is_symlink() or not source.is_file():
            raise ReceiptError(f"Component receipt is missing or unsafe: {source}")
        value = load_json(source)
        safe_dependency_reason = value.get("reason")
        source_sha = value.get("candidateSha")
        if source_sha not in (None, sha):
            raise ReceiptError("Component receipt belongs to a different candidate SHA")
        if value.get("status") not in VERDICT_STATUSES:
            raise ReceiptError("Component receipt has an invalid or missing status")
        if args.kind == "coverage":
            validate_coverage_source(value, claim_value, sha)
            if value.get("status") == "passed" and args.source_root:
                expected_inventory = discover_coverage_inventory(
                    pathlib.Path(args.source_root)
                )
                if value["coverage"]["sourceInventory"] != expected_inventory:
                    raise ReceiptError(
                        "Coverage inventory does not exactly match the candidate source tree"
                    )
        elif args.source_root:
            raise ReceiptError("--source-root is valid only for a coverage receipt")
        # Retain verdict evidence, never raw output, environment data, credentials,
        # or arbitrary provider payloads.
        allowed = {
            "schemaVersion", "status", "startedAtUtc", "finishedAtUtc",
            "scope", "rowCount", "rows", "controllerImageId", "candidateTree",
            "images", "phases", "coverage", "retryCount", "buildCount",
            "failedPhase", "exitCode",
        }
        value = {key: item for key, item in value.items() if key in allowed}
        if (
            isinstance(safe_dependency_reason, str)
            and re.fullmatch(r"not_run_due_to_[a-z0-9_-]+", safe_dependency_reason)
        ):
            value["reason"] = safe_dependency_reason
        if isinstance(value.get("rows"), list):
            row_allowed = {
                "cmdlet", "status", "expected", "category", "errorCode",
                "databaseReadVerified", "databaseWriteVerified", "targetKind",
            }
            value["rows"] = [
                {
                    key: item for key, item in row.items()
                    if key in row_allowed and isinstance(item, (str, bool, int, type(None)))
                }
                for row in value["rows"] if isinstance(row, dict)
            ]
        if args.kind == "build" and isinstance(value.get("images"), dict):
            image_value: dict[str, dict[str, str | None]] = {}
            for name in ("controller", "test", "sshFixture", "verifier"):
                item = value["images"].get(name)
                if isinstance(item, dict):
                    tag = item.get("tag")
                    image_id = item.get("id")
                    image_value[name] = {
                        "tag": tag if isinstance(tag, str) else None,
                        "id": image_id if isinstance(image_id, str) else None,
                    }
            value["images"] = image_value
        if args.kind in {"coverage", "persistence", "security", "orchestration"}:
            if isinstance(value.get("phases"), list):
                phase_allowed = {"name", "status", "exitCode", "reason"}
                value["phases"] = [
                    {
                        key: item for key, item in phase.items()
                        if key in phase_allowed
                        and isinstance(item, (str, int, type(None)))
                    }
                    for phase in value["phases"] if isinstance(phase, dict)
                ]
            if isinstance(value.get("coverage"), dict):
                coverage_allowed = {
                    "status", "minimum", "invocationCount", "testCount", "durationMs",
                    "candidateSha", "candidateTree", "sourceHash", "sourceFileCount",
                    "sourceInventory", "metrics", "uncovered",
                }
                value["coverage"] = {
                    key: item for key, item in value["coverage"].items()
                    if key in coverage_allowed
                    and isinstance(item, (str, int, float, dict, list, type(None)))
                }
                inventory = value["coverage"].get("sourceInventory")
                if isinstance(inventory, list):
                    value["coverage"]["sourceInventory"] = [
                        {
                            "path": item.get("path"),
                            "sha256": item.get("sha256"),
                        }
                        for item in inventory
                        if isinstance(item, dict)
                        and isinstance(item.get("path"), str)
                        and isinstance(item.get("sha256"), str)
                    ]
        value["candidateSha"] = sha
    else:
        if args.status not in VERDICT_STATUSES:
            raise ReceiptError(f"Invalid component status: {args.status!r}")
        if args.kind == "coverage" and args.status == "passed":
            raise ReceiptError("Passing coverage must come from a validated source receipt")
        value = {
            "schemaVersion": 1,
            "candidateSha": sha,
            "status": args.status,
            "reason": args.reason,
            "finishedAtUtc": utc_now(),
        }
    write_exclusive(destination, value)
    print(destination)
    return 0


def seal_value(root: pathlib.Path, sha: str, status: str, phase: str, exit_code: int,
        reason: str, finished: str) -> dict[str, Any]:
    claim_value = load_json(root / "claim.json")
    if claim_value.get("candidateSha") != sha:
        raise ReceiptError("Claim SHA does not match terminal receipt SHA")
    components = {
        kind: load_json(root / f"{kind}-receipt.json")
        if (root / f"{kind}-receipt.json").exists() else None
        for kind in COMPONENT_KINDS
    }
    return {
        "schemaVersion": 1,
        "state": "terminal",
        "attempt": 1,
        "retryCount": 0,
        "status": status,
        "candidateSha": sha,
        "candidateTree": claim_value.get("candidateTree"),
        "startedAtUtc": claim_value.get("startedAtUtc"),
        "finishedAtUtc": finished,
        "terminalPhase": phase,
        "exitCode": exit_code,
        "reason": reason,
        "buildVerdict": verdict_summary(components["build"]),
        "cmdletVerdict": verdict_summary(components["cmdlet"]),
        "windowsQualificationVerdict": verdict_summary(components["windows"]),
        "coverageVerdict": verdict_summary(components["coverage"]),
        "persistenceVerdict": verdict_summary(components["persistence"]),
        "securityVerdict": verdict_summary(components["security"]),
        "releaseProofOrchestrationVerdict": verdict_summary(components["orchestration"]),
    }


def seal(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root)
    sha = validate_sha(args.sha)
    ensure_root_matches(root, sha)
    if args.status not in TERMINAL_STATUSES:
        raise ReceiptError(f"Invalid terminal status: {args.status!r}")
    value = seal_value(root, sha, args.status, args.phase, args.exit_code, args.reason, args.finished)
    write_exclusive(root / "receipt.json", value)
    print(root / "receipt.json")
    return 0


def owner_is_alive(claim_value: dict[str, Any], stale_after: int) -> bool:
    owner = claim_value.get("owner")
    if not isinstance(owner, dict):
        return False
    if owner.get("host") == socket.gethostname():
        try:
            os.kill(int(owner["pid"]), 0)
            return True
        except (KeyError, TypeError, ValueError, ProcessLookupError):
            return False
        except PermissionError:
            return True
    try:
        started = dt.datetime.fromisoformat(str(claim_value.get("startedAtUtc")).replace("Z", "+00:00"))
    except ValueError:
        return False
    return (dt.datetime.now(dt.timezone.utc) - started).total_seconds() < stale_after


def recover(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root)
    sha = validate_sha(args.sha)
    ensure_root_matches(root, sha)
    if (root / "receipt.json").exists():
        raise ReceiptError(f"Exact SHA is already terminal and can never rerun: {sha}")
    claim_value = load_json(root / "claim.json")
    if owner_is_alive(claim_value, args.stale_after):
        raise ReceiptError(f"Exact SHA claim is still active and cannot be taken over: {sha}")
    value = seal_value(root, sha, "aborted", "stale-claim-recovery", 130,
        "The original process ended without sealing; the SHA remains consumed", utc_now())
    write_exclusive(root / "receipt.json", value)
    print(root / "receipt.json")
    return 0


def aggregate(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root)
    terminal = load_json(root / "receipt.json")
    sha = validate_sha(str(terminal.get("candidateSha", "")))
    ensure_root_matches(root, sha)
    paths = {kind: root / f"{kind}-receipt.json" for kind in COMPONENT_KINDS}
    value = {
        "schemaVersion": 1,
        "candidateSha": sha,
        "releaseStatus": terminal.get("status"),
        "buildVerdict": verdict_summary(
            load_json(paths["build"]) if paths["build"].exists() else None
        ),
        "cmdletVerdict": verdict_summary(
            load_json(paths["cmdlet"]) if paths["cmdlet"].exists() else None
        ),
        "windowsQualificationVerdict": verdict_summary(
            load_json(paths["windows"]) if paths["windows"].exists() else None
        ),
        "coverageVerdict": verdict_summary(
            load_json(paths["coverage"]) if paths["coverage"].exists() else None
        ),
        "persistenceVerdict": verdict_summary(
            load_json(paths["persistence"]) if paths["persistence"].exists() else None
        ),
        "securityVerdict": verdict_summary(
            load_json(paths["security"]) if paths["security"].exists() else None
        ),
        "releaseProofOrchestrationVerdict": verdict_summary(
            load_json(paths["orchestration"]) if paths["orchestration"].exists() else None
        ),
        "terminalReceipt": "receipt.json",
        "receiptSha256": {
            "terminal": sha256_file(root / "receipt.json"),
            "build": sha256_file(paths["build"]) if paths["build"].exists() else None,
            "cmdlet": sha256_file(paths["cmdlet"]) if paths["cmdlet"].exists() else None,
            "windowsQualification": sha256_file(paths["windows"]) if paths["windows"].exists() else None,
            "coverage": sha256_file(paths["coverage"]) if paths["coverage"].exists() else None,
            "persistence": sha256_file(paths["persistence"]) if paths["persistence"].exists() else None,
            "security": sha256_file(paths["security"]) if paths["security"].exists() else None,
            "releaseProofOrchestration": (
                sha256_file(paths["orchestration"])
                if paths["orchestration"].exists() else None
            ),
        },
    }
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    item = commands.add_parser("claim")
    item.add_argument("--root", required=True)
    item.add_argument("--sha", required=True)
    item.add_argument("--tree", required=True)
    item.add_argument("--started", required=True)
    item.add_argument("--pid", required=True, type=int)
    item.set_defaults(action=claim)
    item = commands.add_parser("record")
    item.add_argument("--root", required=True)
    item.add_argument("--sha", required=True)
    item.add_argument("--kind", required=True, choices=COMPONENT_KINDS)
    item.add_argument("--source")
    item.add_argument("--status")
    item.add_argument("--reason", default="")
    item.add_argument("--source-root")
    item.set_defaults(action=record)
    item = commands.add_parser("seal")
    item.add_argument("--root", required=True)
    item.add_argument("--sha", required=True)
    item.add_argument("--status", required=True)
    item.add_argument("--phase", required=True)
    item.add_argument("--exit-code", required=True, type=int)
    item.add_argument("--reason", default="")
    item.add_argument("--finished", required=True)
    item.set_defaults(action=seal)
    item = commands.add_parser("recover")
    item.add_argument("--root", required=True)
    item.add_argument("--sha", required=True)
    item.add_argument("--stale-after", type=int, default=86400)
    item.set_defaults(action=recover)
    item = commands.add_parser("aggregate")
    item.add_argument("--root", required=True)
    item.set_defaults(action=aggregate)
    return result


def main() -> int:
    args = build_parser().parse_args()
    try:
        return int(args.action(args))
    except ReceiptError as exc:
        print(str(exc), file=sys.stderr)
        return 73


if __name__ == "__main__":
    raise SystemExit(main())
