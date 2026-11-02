"""Public-proof transport only: give the pinned verifier real Unix pipes.

Node child stdio uses sockets on macOS; the native verifier intentionally
requires FIFO stdin/stdout. Keep that requirement and forward no secret data.
"""
import subprocess
import sys

def main():
    if len(sys.argv) != 2:
        return 1
    raw = sys.stdin.buffer.read(12 * 1024 * 1024 + 1)
    if len(raw) > 12 * 1024 * 1024:
        return 1
    try:
        result = subprocess.run(
            [sys.argv[1], 'verify'], input=raw, capture_output=True,
            timeout=40, env={'PATH': '/usr/bin:/bin', 'RUST_BACKTRACE': '0'},
        )
    except (OSError, subprocess.TimeoutExpired):
        return 1
    if result.returncode != 0 or result.stderr or len(result.stdout) > 32768:
        return 1
    sys.stdout.buffer.write(result.stdout)
    return 0

if __name__ == '__main__':
    sys.exit(main())
