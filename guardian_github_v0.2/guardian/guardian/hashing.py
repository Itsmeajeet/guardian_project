"""Hashing and entropy: the two most basic tools in malware analysis."""

import hashlib
import math
from collections import Counter
from pathlib import Path


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Return the SHA-256 fingerprint of a file.

    A hash is a short fingerprint of a file's exact bytes. Change one byte
    and the fingerprint changes completely. Antivirus companies keep huge
    lists of fingerprints of known-bad files; comparing is instant.

    WHY read in chunks: the file may be huge. Reading 1 MB at a time keeps
    memory use tiny no matter how big the file is.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk_size)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shannon_entropy(data: bytes) -> float:
    """Measure how random the bytes look, from 0.0 to 8.0.

    Normal programs and text have patterns, so entropy is lower (about 4-6.5).
    Packed or encrypted data looks like random noise (about 7.5-8.0).
    Malware authors often pack their code to hide it, so very high entropy in
    an executable is a (weak) warning sign. It is NOT proof: many legitimate
    installers are packed too. That is why we feed it into a score instead of
    treating it as a verdict.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())
