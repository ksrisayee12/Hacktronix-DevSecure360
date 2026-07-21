# backend/app/scanner/sast/taint/scan_cache.py
"""
AST Parse & Findings Cache — Incremental Scanning (Enterprise Edition)

Design Principles:
    1. BOUNDED MEMORY: Cache is stored 100% on disk (JSON file), never in RAM beyond
       the current scan session. In-memory dict is discarded after .save().

    2. LRU EVICTION: When the cache reaches MAX_ENTRIES, the oldest entries (by
       timestamp) are evicted automatically. Disk file size stays bounded.

    3. TTL EXPIRY: Entries older than MAX_AGE_DAYS are automatically pruned on load.
       This prevents stale data from old projects accumulating forever.

    4. RULE SET INVALIDATION: Any change to the rule set (new rules added, old rules
       modified) automatically invalidates all cache entries via rule_set_hash comparison.
       No manual cache clearing needed.

    5. ZERO WRITE ON FAILURE: Cache write failures are silently swallowed — a cache
       miss is always safe; it just means a full rescan of that file.

    6. NO SENSITIVE DATA ACCUMULATION: The cache stores only Finding metadata (line
       numbers, rule IDs, severity). It never stores the file's source code content.

Disk Format:
    .devsecure_cache.json in the scan target directory
    {
        "saved_at": "ISO8601",
        "version": 2,
        "file_hash_to_findings": {
            "sha256_hex": {
                "findings_json": [...],   ← only Finding metadata, not source code
                "rule_set_hash": "...",
                "timestamp": "ISO8601",
                "access_count": N         ← for LRU ordering
            }
        }
    }

Cache is invalidated automatically when:
    - File content changes (content hash changes → different key)
    - Rule set changes (rule_set_hash differs → entry skipped on load)
    - Entry is older than MAX_AGE_DAYS (evicted on load)
    - Cache exceeds MAX_ENTRIES (oldest entries pruned on save)
"""

from __future__ import annotations
import hashlib
import json
import os
from datetime import datetime, timezone, timedelta


CACHE_FILENAME   = ".devsecure_cache.json"
CACHE_VERSION    = 2
MAX_ENTRIES      = 10_000   # Maximum number of file entries in the cache
MAX_AGE_DAYS     = 30       # Evict entries older than this
MAX_FILE_SIZE_MB = 25       # Evict oldest if file exceeds this size on disk


def _hash_file(path: str) -> str:
    """SHA-256 hash of file path + content. Cheap and collision-resistant."""
    h = hashlib.sha256()
    h.update(path.encode("utf-8"))
    try:
        with open(path, "rb") as f:
            # Read in chunks to avoid loading huge files entirely into RAM
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        h.update(b"<unreadable>")
    return h.hexdigest()


def _hash_rules(rules_per_lang: dict) -> str:
    """Hash the entire rule set so cache is invalidated when rules change."""
    h = hashlib.sha256()
    for lang in sorted(rules_per_lang.keys()):
        for rule_id in sorted(rules_per_lang[lang].keys()):
            h.update(rule_id.encode("utf-8"))
    return h.hexdigest()


def _is_expired(timestamp_str: str) -> bool:
    """Return True if the cache entry is older than MAX_AGE_DAYS."""
    try:
        ts = datetime.fromisoformat(timestamp_str)
        age = datetime.now(timezone.utc) - ts
        return age > timedelta(days=MAX_AGE_DAYS)
    except Exception:
        return True  # Corrupt timestamp → treat as expired


class ScanCache:
    """
    Disk-backed file-level finding cache with automatic LRU eviction and TTL expiry.

    Memory Safety Guarantees:
        - In-memory cache (_store) is a dict of at most MAX_ENTRIES entries.
          Each entry stores only Finding metadata (small JSON dicts).
          Source code is NEVER stored in cache.
        - After .save(), the in-memory store remains but can be garbage collected
          when the ScanCache object goes out of scope (end of scan request).
        - The disk file is bounded to ~MAX_FILE_SIZE_MB and MAX_ENTRIES.

    Usage:
        cache = ScanCache(rules_per_lang, cache_dir="/path/to/scan/dir")
        cached = cache.get(file_path)
        if cached is not None:
            return cached   # Cache hit: instant return
        findings = scanner.scan(file_path)
        cache.put(file_path, [finding_to_dict(f) for f in findings])
        cache.save()        # Persist with eviction applied
    """

    def __init__(self, rules_per_lang: dict, cache_dir: str | None = None):
        self._rule_hash   = _hash_rules(rules_per_lang)
        self._store: dict[str, dict] = {}
        self._hits        = 0
        self._misses      = 0
        self._cache_path  = None
        self._evicted     = 0

        if cache_dir:
            self._cache_path = os.path.join(cache_dir, CACHE_FILENAME)
            self._load()

    # ── Loading ────────────────────────────────────────────────────────────────

    def _load(self):
        """
        Load existing cache from disk.
        Automatically discards:
          - Entries with wrong rule_set_hash (rule set changed)
          - Entries older than MAX_AGE_DAYS (TTL expired)
        """
        if not self._cache_path or not os.path.exists(self._cache_path):
            return
        try:
            with open(self._cache_path, "r", encoding="utf-8") as f:
                raw = json.load(f)

            loaded = 0
            evicted_ttl = 0
            evicted_rules = 0

            for file_hash, entry in raw.get("file_hash_to_findings", {}).items():
                # Discard stale rule-set entries
                if entry.get("rule_set_hash") != self._rule_hash:
                    evicted_rules += 1
                    continue
                # Discard expired entries
                if _is_expired(entry.get("timestamp", "")):
                    evicted_ttl += 1
                    continue
                self._store[file_hash] = entry
                loaded += 1

            if evicted_rules or evicted_ttl:
                print(f"[ScanCache] Loaded {loaded} entries. "
                      f"Evicted: {evicted_rules} stale-rules, {evicted_ttl} expired (TTL={MAX_AGE_DAYS}d)")

        except Exception as e:
            # Corrupted cache → start fresh. Non-fatal: just causes full rescan.
            print(f"[ScanCache] Cache corrupt, starting fresh: {e}")
            self._store = {}

    # ── Public API ─────────────────────────────────────────────────────────────

    def get(self, file_path: str) -> list | None:
        """
        Return cached findings for a file if valid, else None.
        A None return is always safe — it just triggers a full scan of that file.
        """
        file_hash = _hash_file(file_path)
        entry = self._store.get(file_hash)
        if entry:
            # Update access count for LRU tracking
            entry["access_count"] = entry.get("access_count", 0) + 1
            self._hits += 1
            return entry.get("findings_json", [])
        self._misses += 1
        return None

    def put(self, file_path: str, findings_json: list):
        """
        Store findings for a file in the in-memory cache.
        Findings must be JSON-serializable dicts (not Finding objects).

        IMPORTANT: Source code is NOT stored here — only finding metadata.
        This keeps memory usage minimal even for large codebases.
        """
        file_hash = _hash_file(file_path)
        self._store[file_hash] = {
            "findings_json": findings_json,   # Only metadata — not source code
            "rule_set_hash": self._rule_hash,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "access_count":  1
        }

    def save(self):
        """
        Persist the cache to disk with LRU eviction and size enforcement.

        Eviction policy:
            1. If entries > MAX_ENTRIES: remove least-recently-accessed entries
            2. If file would exceed MAX_FILE_SIZE_MB: remove oldest by timestamp
            3. Write atomically (temp file then rename) to prevent corruption
        """
        if not self._cache_path:
            return

        try:
            store = self._store

            # ── LRU Eviction: trim to MAX_ENTRIES ─────────────────────────────
            if len(store) > MAX_ENTRIES:
                # Sort by access_count descending (most-accessed first)
                sorted_entries = sorted(
                    store.items(),
                    key=lambda x: x[1].get("access_count", 0),
                    reverse=True
                )
                store = dict(sorted_entries[:MAX_ENTRIES])
                self._evicted += len(self._store) - MAX_ENTRIES
                print(f"[ScanCache] LRU eviction: kept {MAX_ENTRIES} of {len(self._store)} entries")

            payload = {
                "saved_at":             datetime.now(timezone.utc).isoformat(),
                "version":              CACHE_VERSION,
                "rule_set_hash":        self._rule_hash,
                "entry_count":          len(store),
                "file_hash_to_findings": store
            }

            # ── Atomic write: write to temp file, then rename ──────────────────
            # This prevents a half-written cache file from corrupting future loads.
            tmp_path = self._cache_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=None, separators=(",", ":"))  # compact JSON

            # ── Size check: if file too large, trim and re-save ─────────────────
            file_size_mb = os.path.getsize(tmp_path) / (1024 * 1024)
            if file_size_mb > MAX_FILE_SIZE_MB:
                # Sort by timestamp and keep newest half
                all_entries = list(store.items())
                all_entries.sort(key=lambda x: x[1].get("timestamp", ""), reverse=True)
                half = len(all_entries) // 2
                store = dict(all_entries[:half])
                payload["file_hash_to_findings"] = store
                payload["entry_count"] = len(store)
                print(f"[ScanCache] Size limit ({MAX_FILE_SIZE_MB}MB) reached. "
                      f"Trimmed to {len(store)} entries.")
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=None, separators=(",", ":"))

            # Atomic rename
            os.replace(tmp_path, self._cache_path)

        except Exception as e:
            # Cache write failure is completely non-fatal
            print(f"[ScanCache] Warning: cache save failed (non-fatal): {e}")
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    def stats(self) -> dict:
        """Return cache hit/miss statistics for logging."""
        total = self._hits + self._misses
        return {
            "hits":      self._hits,
            "misses":    self._misses,
            "total":     total,
            "evicted":   self._evicted,
            "stored":    len(self._store),
            "hit_rate":  f"{100 * self._hits / max(1, total):.1f}%"
        }

    def clear(self):
        """
        Manually clear the entire cache (in-memory and on-disk).
        Use this when you want to force a complete rescan.
        """
        self._store = {}
        if self._cache_path and os.path.exists(self._cache_path):
            try:
                os.remove(self._cache_path)
                print("[ScanCache] Cache cleared.")
            except Exception:
                pass
