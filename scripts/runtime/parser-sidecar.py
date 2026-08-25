#!/usr/bin/env python3

import hashlib
import json
import os
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any


PROTOCOL = "hosthunter.parser.v1"
MAX_REQUEST_BYTES = 8192
MAX_OUTPUT_LINE_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_TIMEOUT_SECONDS = 300
MAX_EVIDENCE_BYTES = 256 * 1024 * 1024
REQUEST_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_ROOTS = (
    Path("/var/lib/hosthunter-data"),
    Path("/var/lib/hosthunter-secrets"),
    Path("/var/lib/hosthunter-anchors"),
    Path("/var/lib/hosthunter-ssh"),
)


class ProtocolError(Exception):
    """A bounded, operator-safe parser protocol failure."""


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return "unavailable"


def status_value(name: str) -> str:
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if line.startswith(f"{name}:"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unavailable"


def runtime_receipt(evidence_root: Path) -> dict[str, Any]:
    interfaces = sorted(entry.name for entry in Path("/sys/class/net").iterdir())
    forbidden_present = [str(path) for path in FORBIDDEN_ROOTS if path.exists()]
    return {
        "networkInterfaces": interfaces,
        "forbiddenMountsPresent": forbidden_present,
        "rootFilesystemReadOnly": bool(
            os.statvfs("/").f_flag & getattr(os, "ST_RDONLY", 1)
        ),
        "evidenceMountReadOnly": bool(
            os.statvfs(evidence_root).f_flag & getattr(os, "ST_RDONLY", 1)
        ),
        "capabilityEffective": status_value("CapEff"),
        "noNewPrivileges": status_value("NoNewPrivs") == "1",
        "memoryMax": read_text(Path("/sys/fs/cgroup/memory.max")),
        "cpuMax": read_text(Path("/sys/fs/cgroup/cpu.max")),
        "pidsMax": read_text(Path("/sys/fs/cgroup/pids.max")),
    }


def enforce_hardening(receipt: dict[str, Any]) -> None:
    if receipt["networkInterfaces"] != ["lo"]:
        raise RuntimeError("The parser container has a non-loopback network interface.")
    if receipt["forbiddenMountsPresent"]:
        raise RuntimeError("A forbidden controller persistence mount is present.")
    if not receipt["rootFilesystemReadOnly"]:
        raise RuntimeError("The parser root filesystem is not read-only.")
    if not receipt["evidenceMountReadOnly"]:
        raise RuntimeError("The parser evidence mount is not read-only.")
    if receipt["capabilityEffective"] not in ("0000000000000000", "0"):
        raise RuntimeError("The parser retains an effective Linux capability.")
    if not receipt["noNewPrivileges"]:
        raise RuntimeError("The parser does not have no-new-privileges enabled.")
    for limit_name in ("memoryMax", "cpuMax", "pidsMax"):
        if receipt[limit_name] in ("", "max", "unavailable"):
            raise RuntimeError(f"The parser {limit_name} resource limit is unbounded.")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def immutable_stat_identity(file_stat: os.stat_result) -> tuple[int, ...]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_mode,
        file_stat.st_uid,
        file_stat.st_gid,
        file_stat.st_nlink,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )


def open_evidence_beneath(evidence_root: Path, relative_path: PurePosixPath) -> int:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_descriptor = os.open(evidence_root, directory_flags)
    try:
        for component in relative_path.parts[:-1]:
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        return os.open(
            relative_path.parts[-1],
            file_flags,
            dir_fd=directory_descriptor,
        )
    finally:
        os.close(directory_descriptor)


def receive_request(connection: socket.socket) -> dict[str, Any]:
    connection.settimeout(5.0)
    request_bytes = bytearray()
    while b"\n" not in request_bytes:
        chunk = connection.recv(1024)
        if not chunk:
            raise ProtocolError("The request ended before its newline terminator.")
        request_bytes.extend(chunk)
        if len(request_bytes) > MAX_REQUEST_BYTES:
            raise ProtocolError("The request exceeded 8192 bytes.")
    line, trailing = bytes(request_bytes).split(b"\n", 1)
    if trailing:
        raise ProtocolError("Exactly one request is allowed per connection.")
    try:
        request = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("The request is not valid UTF-8 JSON.") from error
    if not isinstance(request, dict):
        raise ProtocolError("The request must be a JSON object.")
    return request


def validate_request(request: dict[str, Any], evidence_root: Path) -> dict[str, Any]:
    required = {"protocol", "request_id", "relative_path", "expected_sha256"}
    optional = {"timeout_seconds", "max_line_bytes"}
    if set(request) - required - optional or required - set(request):
        raise ProtocolError("The request field inventory is invalid.")
    if request["protocol"] != PROTOCOL:
        raise ProtocolError("The parser protocol version is unsupported.")
    request_id = request["request_id"]
    if not isinstance(request_id, str) or not REQUEST_ID_PATTERN.fullmatch(request_id):
        raise ProtocolError("request_id must be 32 lowercase hexadecimal characters.")
    expected_hash = request["expected_sha256"]
    if not isinstance(expected_hash, str) or not SHA256_PATTERN.fullmatch(expected_hash):
        raise ProtocolError("expected_sha256 must be lowercase SHA-256.")
    relative_value = request["relative_path"]
    if not isinstance(relative_value, str) or len(relative_value.encode("utf-8")) > 1024:
        raise ProtocolError("relative_path is invalid or too long.")
    relative_path = PurePosixPath(relative_value)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ProtocolError("relative_path must remain beneath the evidence root.")
    if relative_path.suffix.lower() != ".evtx":
        raise ProtocolError("The parser accepts only EVTX input.")
    try:
        descriptor = open_evidence_beneath(evidence_root, relative_path)
    except OSError as error:
        raise ProtocolError(
            "The EVTX input is missing, linked, outside the root, or unreadable."
        ) from error
    try:
        candidate_stat = os.fstat(descriptor)
        if not stat.S_ISREG(candidate_stat.st_mode) or candidate_stat.st_nlink != 1:
            raise ProtocolError("The EVTX input must be one regular non-link file.")
        if candidate_stat.st_uid != os.getuid():
            raise ProtocolError("The EVTX input must be owned by the parser runtime identity.")
        if candidate_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ProtocolError("The EVTX input cannot be group- or world-writable.")
        if candidate_stat.st_size <= 0 or candidate_stat.st_size > MAX_EVIDENCE_BYTES:
            raise ProtocolError("The EVTX input size is outside the 256 MiB bound.")
        actual_hash = sha256_descriptor(descriptor)
    except Exception:
        os.close(descriptor)
        raise
    if actual_hash != expected_hash:
        os.close(descriptor)
        raise ProtocolError("The EVTX input hash does not match expected_sha256.")
    timeout_seconds = request.get("timeout_seconds", 120)
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ProtocolError("timeout_seconds must be an integer from 1 through 300.")
    max_line_bytes = request.get("max_line_bytes", 1024 * 1024)
    if not isinstance(max_line_bytes, int) or not 1024 <= max_line_bytes <= MAX_OUTPUT_LINE_BYTES:
        raise ProtocolError("max_line_bytes must be from 1024 through 4194304.")
    return {
        "request_id": request_id,
        "descriptor": descriptor,
        "stat_identity": immutable_stat_identity(candidate_stat),
        "input_sha256": actual_hash,
        "timeout_seconds": timeout_seconds,
        "max_line_bytes": max_line_bytes,
    }


def send_frame(connection: socket.socket, frame: dict[str, Any]) -> None:
    encoded = json.dumps(frame, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    connection.sendall(encoded + b"\n")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("The EVTX parser could not be reaped.") from error


def stream_parser(
    connection: socket.socket,
    request: dict[str, Any],
    parser_binary: Path,
    parser_sha256: str,
    receipt: dict[str, Any],
) -> None:
    process = subprocess.Popen(
        [
            str(parser_binary),
            "-t",
            "1",
            "-o",
            "jsonl",
            f"/proc/self/fd/{request['descriptor']}",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(request["descriptor"],),
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    record_count = 0
    deadline = time.monotonic() + request["timeout_seconds"]
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProtocolError("The EVTX parser exceeded timeout_seconds.")
            events = selector.select(min(remaining, 1.0))
            if not events and process.poll() is not None:
                for key in list(selector.get_map().values()):
                    selector.unregister(key.fileobj)
                break
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stderr":
                    stderr_buffer.extend(chunk)
                    if len(stderr_buffer) > MAX_STDERR_BYTES:
                        raise ProtocolError("The EVTX parser stderr exceeded its bound.")
                    continue
                stdout_buffer.extend(chunk)
                while b"\n" in stdout_buffer:
                    line, remainder = stdout_buffer.split(b"\n", 1)
                    stdout_buffer = bytearray(remainder)
                    if len(line) > request["max_line_bytes"]:
                        raise ProtocolError("An EVTX JSONL record exceeded max_line_bytes.")
                    if not line.strip():
                        continue
                    try:
                        record_json = line.decode("utf-8")
                        json.loads(record_json)
                    except (UnicodeDecodeError, json.JSONDecodeError) as error:
                        raise ProtocolError("The EVTX parser emitted invalid JSONL.") from error
                    send_frame(
                        connection,
                        {
                            "protocol": PROTOCOL,
                            "kind": "record",
                            "request_id": request["request_id"],
                            "ordinal": record_count,
                            "provisional": True,
                            "record_json": record_json,
                            "record_sha256": hashlib.sha256(line).hexdigest(),
                        },
                    )
                    record_count += 1
                if len(stdout_buffer) > request["max_line_bytes"]:
                    raise ProtocolError("An EVTX JSONL record exceeded max_line_bytes.")
        exit_code = process.wait(timeout=2)
        if stdout_buffer.strip():
            raise ProtocolError("The EVTX parser ended with an unterminated JSONL record.")
        if exit_code != 0:
            raise ProtocolError(
                f"The EVTX parser exited {exit_code}; stderr_sha256="
                f"{hashlib.sha256(stderr_buffer).hexdigest()}."
            )
        final_stat = os.fstat(request["descriptor"])
        final_hash = sha256_descriptor(request["descriptor"])
        if (
            immutable_stat_identity(final_stat) != request["stat_identity"]
            or final_hash != request["input_sha256"]
        ):
            raise ProtocolError(
                "The EVTX input changed while provisional parser records were streaming."
            )
        send_frame(
            connection,
            {
                "protocol": PROTOCOL,
                "kind": "complete",
                "request_id": request["request_id"],
                "record_count": record_count,
                "input_sha256": request["input_sha256"],
                "parser_sha256": parser_sha256,
                "parser_version": "0.12.2",
                "runtime": receipt,
            },
        )
    finally:
        selector.close()
        stop_process(process)


def handle_connection(
    connection: socket.socket,
    evidence_root: Path,
    parser_binary: Path,
    parser_sha256: str,
    receipt: dict[str, Any],
) -> None:
    request_id = "unknown"
    request: dict[str, Any] | None = None
    try:
        if hasattr(socket, "SO_PEERCRED"):
            credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            _, peer_uid, _ = struct.unpack("3i", credentials)
            if peer_uid != os.getuid():
                raise ProtocolError("The Unix-socket peer UID is not authorized.")
        raw_request = receive_request(connection)
        if isinstance(raw_request.get("request_id"), str):
            request_id = raw_request["request_id"]
        request = validate_request(raw_request, evidence_root)
        stream_parser(connection, request, parser_binary, parser_sha256, receipt)
    except (BrokenPipeError, ConnectionResetError):
        return
    except ProtocolError as error:
        try:
            send_frame(
                connection,
                {
                    "protocol": PROTOCOL,
                    "kind": "error",
                    "request_id": request_id,
                    "error": str(error),
                },
            )
        except OSError:
            pass
    finally:
        if request is not None and "descriptor" in request:
            os.close(request["descriptor"])


def main() -> int:
    os.umask(0o077)
    socket_path = Path(os.environ.get("HH_PARSER_SOCKET", ""))
    evidence_root = Path(os.environ.get("HH_PARSER_EVIDENCE_ROOT", ""))
    parser_binary = Path(os.environ.get("HH_PARSER_BINARY", ""))
    if not socket_path.is_absolute() or not evidence_root.is_absolute():
        raise RuntimeError("Parser socket and evidence roots must be absolute.")
    if not parser_binary.is_absolute() or not parser_binary.is_file():
        raise RuntimeError("The pinned EVTX parser binary is unavailable.")
    if parser_binary.is_symlink() or not evidence_root.is_dir() or evidence_root.is_symlink():
        raise RuntimeError("Parser paths must be non-link files and directories.")
    parser_sha256 = sha256_file(parser_binary)
    expected_sha256 = read_text(Path(f"{parser_binary}.sha256")).split(" ", 1)[0]
    if parser_sha256 != expected_sha256:
        raise RuntimeError("The pinned EVTX parser digest is invalid.")
    receipt = runtime_receipt(evidence_root)
    if os.environ.get("HH_PARSER_REQUIRE_HARDENING") == "1":
        enforce_hardening(receipt)

    socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if socket_path.exists() or socket_path.is_socket():
        socket_stat = socket_path.lstat()
        if not stat.S_ISSOCK(socket_stat.st_mode) or socket_stat.st_uid != os.getuid():
            raise RuntimeError("The parser socket path is occupied by an unsafe object.")
        socket_path.unlink()

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        server.listen(4)
        while True:
            connection, _ = server.accept()
            with connection:
                handle_connection(
                    connection,
                    evidence_root,
                    parser_binary,
                    parser_sha256,
                    receipt,
                )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"HostHunter parser sidecar refused startup: {error}", file=sys.stderr)
        sys.exit(70)
