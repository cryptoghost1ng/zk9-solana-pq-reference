"""Serialize this candidate's isolated offline checks, not the user's app.

These checks neither start a validator nor publish transactions. They read
frozen public fixtures, write new candidate directories, and do not measure
performance. Live settlement/prover benchmarks still require an idle lab.
"""
import fcntl
from pathlib import Path


def acquire():
    lock = (Path(__file__).resolve().parent / 'offline.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        raise RuntimeError('Another candidate offline check is still running.')
    return lock
