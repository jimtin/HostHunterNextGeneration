#!/usr/bin/env python3

import os
import socket
import stat
import sys


def main() -> int:
    socket_path = os.environ.get(
        "HH_PARSER_SOCKET", "/run/hosthunter-parser/parser.sock"
    )
    try:
        socket_stat = os.lstat(socket_path)
    except OSError:
        return 1
    if not stat.S_ISSOCK(socket_stat.st_mode):
        return 1
    if stat.S_IMODE(socket_stat.st_mode) != 0o600:
        return 1
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(1.0)
            client.connect(socket_path)
    except OSError:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
