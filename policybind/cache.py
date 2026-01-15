"""
Caching utilities for PolicyBind.

This module provides thread-safe caching implementations with TTL support,
LRU eviction, and performance statistics for optimizing PolicyBind operations.
"""

import hashlib
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Generic, TypeVar

from policybind.models.base import utc_now

T = TypeVar("T")


@dataclass
class CacheEntry(Generic[T]):
    """
    A cached entry with metadata.

    Attributes:
        value: The cached value.
        created_at: When the entry was created.
        expires_at: When the entry expires.
        access_count: Number of times the entry was accessed.
        last_accessed: When the entry was last accessed.
    """

    value: T
    created_at: datetime = field(default_factory=utc_now)
    expires_at: datetime | None = None
    access_count: int = 0
    last_accessed: datetime = field(default_factory=utc_now)

    def is_expired(self) -> bool:
        """Check if the entry has expired."""
        if self.expires_at is None:
            return False
        return utc_now() > self.expires_at

    def touch(self) -> None:
        """Update access metadata."""
        self.access_count += 1
        self.last_accessed = utc_now()


@dataclass
class CacheStats:
    """
    Statistics about cache performance.

    Attributes:
        hits: Number of cache hits.
        misses: Number of cache misses.
        evictions: Number of entries evicted.
        expired: Number of entries that expired.
        size: Current number of entries.
        max_size: Maximum cache size.
    """

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expired: int = 0
    size: int = 0
    max_size: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate the cache hit rate."""
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.hits / total

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "expired": self.expired,
            "size": self.size,
            "max_size": self.max_size,
            "hit_rate": self.hit_rate,
        }


class TTLCache(Generic[T]):
    """
    Thread-safe cache with time-to-live expiration.

    Entries automatically expire after their TTL has passed.
    The cache uses lazy expiration - entries are only removed
    when accessed or during periodic cleanup.

    Example:
        Using the cache::

            cache = TTLCache[str](ttl_seconds=60, max_size=1000)
            cache.set("key1", "value1")

            value = cache.get("key1")
            if value is not None:
                print(f"Found: {value}")

    Thread Safety:
        All operations are thread-safe through internal locking.
    """

    def __init__(
        self,
        ttl_seconds: int = 300,
        max_size: int = 10000,
        cleanup_interval: int = 60,
    ) -> None:
        """
        Initialize the cache.

        Args:
            ttl_seconds: Time-to-live for cache entries in seconds.
            max_size: Maximum number of entries in the cache.
            cleanup_interval: How often to run cleanup (in seconds).
        """
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._cleanup_interval = cleanup_interval
        self._cache: OrderedDict[str, CacheEntry[T]] = OrderedDict()
        self._lock = threading.RLock()
        self._stats = CacheStats(max_size=max_size)
        self._last_cleanup = time.time()

    def get(self, key: str) -> T | None:
        """
        Get a value from the cache.

        Args:
            key: The cache key.

        Returns:
            The cached value, or None if not found or expired.
        """
        with self._lock:
            entry = self._cache.get(key)

            if entry is None:
                self._stats.misses += 1
                return None

            if entry.is_expired():
                self._remove_entry(key, expired=True)
                self._stats.misses += 1
                return None

            entry.touch()
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._stats.hits += 1
            return entry.value

    def set(
        self,
        key: str,
        value: T,
        ttl_seconds: int | None = None,
    ) -> None:
        """
        Set a value in the cache.

        Args:
            key: The cache key.
            value: The value to cache.
            ttl_seconds: Optional custom TTL for this entry.
        """
        with self._lock:
            # Check if we need to evict
            if len(self._cache) >= self._max_size and key not in self._cache:
                self._evict_oldest()

            ttl = ttl_seconds if ttl_seconds is not None else self._ttl
            expires_at = utc_now() + timedelta(seconds=ttl)

            self._cache[key] = CacheEntry(
                value=value,
                expires_at=expires_at,
            )
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._stats.size = len(self._cache)

            # Periodic cleanup
            self._maybe_cleanup()

    def delete(self, key: str) -> bool:
        """
        Delete an entry from the cache.

        Args:
            key: The cache key.

        Returns:
            True if the entry was deleted, False if not found.
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._stats.size = len(self._cache)
                return True
            return False

    def clear(self) -> None:
        """Clear all entries from the cache."""
        with self._lock:
            self._cache.clear()
            self._stats.size = 0

    def contains(self, key: str) -> bool:
        """
        Check if a key exists and is not expired.

        Args:
            key: The cache key.

        Returns:
            True if the key exists and is not expired.
        """
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return False
            if entry.is_expired():
                self._remove_entry(key, expired=True)
                return False
            return True

    def get_or_set(
        self,
        key: str,
        factory: Callable[[], T],
        ttl_seconds: int | None = None,
    ) -> T:
        """
        Get a value from cache, or compute and cache it if missing.

        Args:
            key: The cache key.
            factory: Function to compute the value if not cached.
            ttl_seconds: Optional custom TTL for this entry.

        Returns:
            The cached or computed value.
        """
        value = self.get(key)
        if value is not None:
            return value

        # Compute the value
        value = factory()
        self.set(key, value, ttl_seconds)
        return value

    def get_stats(self) -> CacheStats:
        """
        Get cache statistics.

        Returns:
            CacheStats with current statistics.
        """
        with self._lock:
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                expired=self._stats.expired,
                size=len(self._cache),
                max_size=self._max_size,
            )

    def reset_stats(self) -> None:
        """Reset cache statistics."""
        with self._lock:
            self._stats = CacheStats(
                max_size=self._max_size,
                size=len(self._cache),
            )

    def _evict_oldest(self) -> None:
        """Evict the oldest entry (LRU)."""
        if self._cache:
            # OrderedDict maintains insertion order, first item is oldest
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
            self._stats.evictions += 1

    def _remove_entry(self, key: str, expired: bool = False) -> None:
        """Remove an entry from the cache."""
        if key in self._cache:
            del self._cache[key]
            if expired:
                self._stats.expired += 1

    def _maybe_cleanup(self) -> None:
        """Run cleanup if enough time has passed."""
        now = time.time()
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup()
            self._last_cleanup = now

    def _cleanup(self) -> None:
        """Remove expired entries."""
        expired_keys = [
            key for key, entry in self._cache.items() if entry.is_expired()
        ]
        for key in expired_keys:
            self._remove_entry(key, expired=True)
        self._stats.size = len(self._cache)


class PolicyCache:
    """
    Specialized cache for policy-related data.

    Provides caching for:
    - Compiled policy conditions
    - Policy match results
    - Policy set metadata

    Example:
        Using the policy cache::

            cache = PolicyCache()

            # Cache a match result
            cache.cache_match("req-123", match_result)

            # Get cached result
            cached = cache.get_match("req-123")
    """

    def __init__(
        self,
        condition_ttl: int = 3600,
        match_ttl: int = 60,
        max_conditions: int = 1000,
        max_matches: int = 10000,
    ) -> None:
        """
        Initialize the policy cache.

        Args:
            condition_ttl: TTL for compiled conditions (seconds).
            match_ttl: TTL for match results (seconds).
            max_conditions: Maximum cached conditions.
            max_matches: Maximum cached match results.
        """
        self._conditions: TTLCache[Any] = TTLCache(
            ttl_seconds=condition_ttl,
            max_size=max_conditions,
        )
        self._matches: TTLCache[Any] = TTLCache(
            ttl_seconds=match_ttl,
            max_size=max_matches,
        )
        self._policy_version: str = ""

    def set_policy_version(self, version: str) -> None:
        """
        Set the current policy version.

        When the version changes, match cache is invalidated.

        Args:
            version: The new policy version.
        """
        if version != self._policy_version:
            self._matches.clear()
            self._policy_version = version

    def get_condition(self, rule_id: str) -> Any | None:
        """Get a cached compiled condition."""
        return self._conditions.get(rule_id)

    def cache_condition(self, rule_id: str, condition: Any) -> None:
        """Cache a compiled condition."""
        self._conditions.set(rule_id, condition)

    def get_match(self, request_hash: str) -> Any | None:
        """Get a cached match result."""
        key = f"{self._policy_version}:{request_hash}"
        return self._matches.get(key)

    def cache_match(self, request_hash: str, result: Any) -> None:
        """Cache a match result."""
        key = f"{self._policy_version}:{request_hash}"
        self._matches.set(key, result)

    def clear_matches(self) -> None:
        """Clear all cached match results."""
        self._matches.clear()

    def clear_conditions(self) -> None:
        """Clear all cached conditions."""
        self._conditions.clear()

    def clear_all(self) -> None:
        """Clear all caches."""
        self._conditions.clear()
        self._matches.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return {
            "conditions": self._conditions.get_stats().to_dict(),
            "matches": self._matches.get_stats().to_dict(),
            "policy_version": self._policy_version,
        }


def create_cache_key(*args: Any) -> str:
    """
    Create a cache key from multiple arguments.

    Args:
        args: Values to include in the key.

    Returns:
        A hash-based cache key.
    """
    parts = []
    for arg in args:
        if arg is None:
            parts.append("null")
        elif isinstance(arg, (list, tuple)):
            parts.append(",".join(str(x) for x in sorted(arg)))
        elif isinstance(arg, dict):
            sorted_items = sorted(arg.items())
            parts.append(",".join(f"{k}={v}" for k, v in sorted_items))
        else:
            parts.append(str(arg))

    combined = "|".join(parts)
    return hashlib.md5(combined.encode()).hexdigest()
