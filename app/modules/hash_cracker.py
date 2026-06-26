"""
CyberKit — Hash dictionary-attack engine.

Thread-safe; results delivered via queue.Queue.
"""

import hashlib
import queue
import threading
from dataclasses import dataclass


SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")

_ALGO_NORMALISE = {
    "md5": "md5", "sha1": "sha1", "sha-1": "sha1",
    "sha256": "sha256", "sha-256": "sha256",
    "sha512": "sha512", "sha-512": "sha512",
}


@dataclass
class CrackResult:
    found:    bool
    word:     str  = ""
    progress: int  = 0
    total:    int  = 0
    done:     bool = False


class HashCrackEngine:
    def __init__(
        self,
        hash_str:    str,
        algorithm:   str,
        wordlist:    list,
        result_queue: queue.Queue,
        stop_event:  threading.Event,
    ):
        algo = _ALGO_NORMALISE.get(algorithm.lower().strip())
        if algo is None:
            raise ValueError(
                f"Unsupported algorithm '{algorithm}'. "
                f"Supported: {', '.join(SUPPORTED_ALGORITHMS)}"
            )
        self._hash  = hash_str.strip().lower()
        self._algo  = algo
        self._words = wordlist
        self._queue = result_queue
        self._stop  = stop_event

    def run(self):
        total = len(self._words)
        for i, word in enumerate(self._words, 1):
            if self._stop.is_set():
                break
            digest = hashlib.new(
                self._algo, word.encode("utf-8", errors="replace")
            ).hexdigest()
            if digest == self._hash:
                self._queue.put(
                    CrackResult(found=True, word=word, progress=i, total=total, done=True)
                )
                return
            if i % 500 == 0 or i == total:
                self._queue.put(CrackResult(found=False, progress=i, total=total))
        self._queue.put(CrackResult(found=False, progress=total, total=total, done=True))
