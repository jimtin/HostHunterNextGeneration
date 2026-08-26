#!/usr/bin/env python3
"""Immutable, once-per-SHA release receipt state machine."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import socket
import sys
from typing import Any


TERMINAL_STATUSES = {"passed", "failed", "blocked", "aborted"}
VERDICT_STATUSES = TERMINAL_STATUSES | {"not-run"}
COMPONENT_KINDS = ("build", "cmdlet", "windows", "heavy")


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
    load_json(root / "claim.json")
    if (root / "receipt.json").exists():
        raise ReceiptError("Cannot add a component verdict after terminal sealing")
    destination = root / f"{args.kind}-receipt.json"
    if args.source:
        source = pathlib.Path(args.source)
        if source.is_symlink() or not source.is_file():
            raise ReceiptError(f"Component receipt is missing or unsafe: {source}")
        value = load_json(source)
        source_sha = value.get("candidateSha")
        if source_sha not in (None, sha):
            raise ReceiptError("Component receipt belongs to a different candidate SHA")
        if value.get("status") not in VERDICT_STATUSES:
            raise ReceiptError("Component receipt has an invalid or missing status")
        # Retain verdict evidence, never raw output, environment data, credentials,
        # or arbitrary provider payloads.
        allowed = {
            "schemaVersion", "status", "startedAtUtc", "finishedAtUtc",
            "scope", "rowCount", "rows", "controllerImageId", "candidateTree",
            "images", "phases", "coverage", "retryCount", "buildCount",
            "failedPhase", "exitCode",
        }
        value = {key: item for key, item in value.items() if key in allowed}
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
        if args.kind == "heavy":
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
                    "sourceInventory", "metrics",
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
        "heavyProofVerdict": verdict_summary(components["heavy"]),
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
        "heavyProofVerdict": verdict_summary(
            load_json(paths["heavy"]) if paths["heavy"].exists() else None
        ),
        "terminalReceipt": "receipt.json",
        "receiptSha256": {
            "terminal": sha256_file(root / "receipt.json"),
            "build": sha256_file(paths["build"]) if paths["build"].exists() else None,
            "cmdlet": sha256_file(paths["cmdlet"]) if paths["cmdlet"].exists() else None,
            "windowsQualification": sha256_file(paths["windows"]) if paths["windows"].exists() else None,
            "heavyProof": sha256_file(paths["heavy"]) if paths["heavy"].exists() else None,
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
