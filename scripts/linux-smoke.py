#!/usr/bin/env python3
"""End-to-end FUSE tests. Run as root inside a disposable Linux VM.
A random test key is delivered via a PTY, never argv/environment or logs.
"""
import argparse
import errno
import os
from pathlib import Path
import pty
import secrets
import select
import signal
import tempfile
import termios
import time

parser = argparse.ArgumentParser()
parser.add_argument('--binary', default='target/debug/vault-lab')
parser.add_argument('--plugin', default='lib/libaldcrypto.so')
parser.add_argument('--crypto-only', action='store_true')
args = parser.parse_args()
binary = str(Path(args.binary).resolve())
plugin = str(Path(args.plugin).resolve())
if not args.crypto_only and (os.geteuid() != 0 or not Path('/dev/fuse').exists()):
    raise SystemExit('FUSE tests require root and /dev/fuse; use --crypto-only for storage checks')
key = secrets.token_hex(32).encode()

def run(arguments, expected=0, supplied=key):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(binary, [binary, '--plugin', plugin, *map(str, arguments)])
    deadline = time.monotonic() + 90
    output = bytearray()
    sent = False
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    part = os.read(fd, 65536)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    break
                if not part:
                    break
                output.extend(part)
            if not sent and b'Key (64 hex characters, hidden): ' in output:
                if not (termios.tcgetattr(fd)[3] & termios.ECHO):
                    os.write(fd, supplied + b'\n')
                    sent = True
        else:
            raise TimeoutError('Test process exceeded 90 seconds')
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        text = output.decode(errors='replace').replace(supplied.decode(), '[REDACTED]')
        if (expected == 0 and code != 0) or (expected != 0 and code == 0):
            raise RuntimeError(f'{arguments}: exit {code}\n{text}')
        print(text.strip())
    finally:
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        os.close(fd)

with tempfile.TemporaryDirectory(prefix='vault-smoke-') as directory:
    vault = Path(directory) / 'store.sbox'
    run(['init', vault])
    run(['check', vault])
    run(['check', vault], expected=1, supplied=secrets.token_hex(32).encode())
    if not args.crypto_only:
        run(['open', vault, '--test'])
        run(['open', vault, '--verify'])
        run(['open', vault, '--test', '--attack'])
        run(['open', vault, '--verify'])
        assert b'vault-probe persisted' not in vault.read_bytes()
    raw = bytearray(vault.read_bytes())
    raw[len(raw) // 2] ^= 1
    vault.write_bytes(raw)
    run(['check', vault], expected=1)
print('PASS: crypto/storage smoke' if args.crypto_only else 'PASS: Linux FUSE smoke including mount substitution')
