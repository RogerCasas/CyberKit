"""
CyberKit — Wordlist Generator Engine

Two modes:
  BruteforceGenerator  — itertools.product over a charset
  MutationGenerator    — leet/caps/suffix transforms on seed phrases

Both are lazy iterators; generate_to_file writes to disk in the background.
"""

import itertools
import threading
from typing import Callable, Generator, Iterator, Optional

LEET_MAP: dict[str, str] = {
    'a': '@', 'e': '3', 'i': '1',
    'o': '0', 's': '$', 't': '7',
}

MAX_ENTRIES = 1_000_000


# ── Generators ────────────────────────────────────────────────────────────────

class BruteforceGenerator:
    def __init__(self, charset: str, min_len: int, max_len: int) -> None:
        self.charset  = charset
        self.min_len  = max(1, min_len)
        self.max_len  = max(self.min_len, max_len)

    def __iter__(self) -> Iterator[str]:
        for length in range(self.min_len, self.max_len + 1):
            for combo in itertools.product(self.charset, repeat=length):
                yield "".join(combo)

    def estimated_count(self) -> int:
        base = len(self.charset)
        return sum(base ** l for l in range(self.min_len, self.max_len + 1))


class MutationGenerator:
    def __init__(
        self,
        seeds: list[str],
        leet:     bool = False,
        lower:    bool = True,
        upper:    bool = False,
        title:    bool = False,
        suffixes: bool = False,
        suffix_range: tuple[int, int] = (1, 99),
        prefix: str = "",
        suffix: str = "",
    ) -> None:
        self.seeds        = [s for s in seeds if s]
        self.leet         = leet
        self.lower        = lower
        self.upper        = upper
        self.title        = title
        self.suffixes     = suffixes
        self.suffix_range = suffix_range
        self.prefix       = prefix
        self.suffix       = suffix

    def _variants(self, seed: str) -> list[str]:
        base: list[str] = []
        if self.lower:
            base.append(seed.lower())
        if self.upper:
            base.append(seed.upper())
        if self.title:
            base.append(seed.capitalize())
        if self.leet:
            leetd = "".join(LEET_MAP.get(c, c) for c in seed.lower())
            base.append(leetd)
        if not base:
            base.append(seed)
        return base

    def __iter__(self) -> Iterator[str]:
        for seed in self.seeds:
            for variant in self._variants(seed):
                word = self.prefix + variant + self.suffix
                yield word
                if self.suffixes:
                    for n in range(self.suffix_range[0], self.suffix_range[1] + 1):
                        yield word + str(n)

    def estimated_count(self) -> int:
        per_seed = 0
        n_rules = sum([self.lower, self.upper, self.title, self.leet]) or 1
        if self.suffixes:
            n_num = self.suffix_range[1] - self.suffix_range[0] + 1
            per_seed = n_rules * (1 + n_num)
        else:
            per_seed = n_rules
        return len(self.seeds) * per_seed


# ── File writer ───────────────────────────────────────────────────────────────

def generate_to_file(
    generator,
    path: str,
    on_progress: Callable[[int], None],
    stop_event: threading.Event,
    cap: int = MAX_ENTRIES,
) -> int:
    """Write wordlist to *path* line by line. Returns number of entries written."""
    written = 0
    buf: list[str] = []
    with open(path, "w", encoding="utf-8") as fh:
        for word in generator:
            if stop_event.is_set() or written >= cap:
                break
            buf.append(word)
            written += 1
            if len(buf) >= 1000:
                fh.write("\n".join(buf) + "\n")
                buf.clear()
                on_progress(written)
        if buf:
            fh.write("\n".join(buf) + "\n")
            on_progress(written)
    return written
