"""
Policy hot reloading for PolicyBind.

This module provides the PolicyReloader class for watching policy files
and reloading them without restarting the service.
"""

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from policybind.engine.parser import PolicyParser
from policybind.engine.validator import PolicyValidator, ValidationResult
from policybind.engine.versioning import PolicyVersion, PolicyVersionManager
from policybind.exceptions import PolicyError
from policybind.models.base import generate_uuid, utc_now
from policybind.models.policy import PolicySet


class ReloadTrigger(Enum):
    """How the reload was triggered."""

    FILE_CHANGE = "file_change"
    """Automatic reload from file system change."""

    MANUAL = "manual"
    """Manual reload triggered via API or CLI."""

    STARTUP = "startup"
    """Initial load at startup."""

    ROLLBACK = "rollback"
    """Rollback to previous version."""


@dataclass
class ReloadEvent:
    """
    Represents a policy reload event.

    Attributes:
        event_id: Unique identifier for this event.
        trigger: How the reload was triggered.
        timestamp: When the event occurred.
        success: Whether the reload succeeded.
        version: The new version number if successful.
        policy_name: Name of the policy that was reloaded.
        source_files: Files that were loaded.
        error: Error message if reload failed.
        validation_result: Result of policy validation.
        duration_ms: How long the reload took.
    """

    event_id: str
    trigger: ReloadTrigger
    timestamp: str
    success: bool
    version: int | None = None
    policy_name: str = ""
    source_files: list[str] = field(default_factory=list)
    error: str = ""
    validation_result: ValidationResult | None = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert event to a dictionary."""
        return {
            "event_id": self.event_id,
            "trigger": self.trigger.value,
            "timestamp": self.timestamp,
            "success": self.success,
            "version": self.version,
            "policy_name": self.policy_name,
            "source_files": self.source_files,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


# Type alias for reload callbacks
ReloadCallback = Callable[[ReloadEvent], None]


class PolicyReloader:
    """
    Watches policy files and reloads them without service restart.

    The PolicyReloader provides:
    - File system watching for policy file changes
    - Validation of new policies before applying
    - Atomic swapping of the active policy set
    - Maintaining previous version for rollback
    - Event emission when policies are reloaded
    - Manual reload triggers via API or CLI

    The reloader guarantees that no request is ever evaluated against
    a partially-loaded policy set by using atomic reference swapping.

    Example:
        Using the policy reloader::

            reloader = PolicyReloader(
                policy_paths=["policies/main.yaml"],
                auto_reload=True,
            )

            # Register callback
            reloader.on_reload(lambda event: print(f"Reloaded: {event}"))

            # Start watching
            reloader.start()

            # Get current policy
            policy = reloader.get_active_policy()

            # Manual reload
            reloader.reload()

            # Rollback
            reloader.rollback(version=1)

            # Stop watching
            reloader.stop()
    """

    def __init__(
        self,
        policy_paths: list[str | Path] | None = None,
        auto_reload: bool = True,
        poll_interval: float = 1.0,
        validate_before_reload: bool = True,
        max_versions: int = 100,
    ) -> None:
        """
        Initialize the policy reloader.

        Args:
            policy_paths: Paths to policy YAML files to watch.
            auto_reload: Whether to automatically reload on file changes.
            poll_interval: Seconds between file change checks.
            validate_before_reload: Whether to validate policies before applying.
            max_versions: Maximum number of versions to retain.
        """
        self._policy_paths: list[Path] = []
        if policy_paths:
            self._policy_paths = [Path(p) for p in policy_paths]

        self._auto_reload = auto_reload
        self._poll_interval = poll_interval
        self._validate_before_reload = validate_before_reload

        # Thread safety
        self._lock = threading.RLock()
        self._policy_lock = threading.RLock()

        # Current policy (atomic reference)
        self._active_policy: PolicySet | None = None

        # Components
        self._parser = PolicyParser()
        self._validator = PolicyValidator()
        self._version_manager = PolicyVersionManager(max_versions=max_versions)

        # File watching
        self._watching = False
        self._watch_thread: threading.Thread | None = None
        self._file_mtimes: dict[str, float] = {}

        # Callbacks
        self._reload_callbacks: list[ReloadCallback] = []

        # Event history
        self._events: list[ReloadEvent] = []
        self._max_events = 100

    def add_policy_path(self, path: str | Path) -> None:
        """
        Add a policy file path to watch.

        Args:
            path: Path to a policy YAML file.
        """
        with self._lock:
            path = Path(path)
            if path not in self._policy_paths:
                self._policy_paths.append(path)
                if path.exists():
                    self._file_mtimes[str(path)] = path.stat().st_mtime

    def remove_policy_path(self, path: str | Path) -> bool:
        """
        Remove a policy file path from watching.

        Args:
            path: Path to remove.

        Returns:
            True if the path was removed.
        """
        with self._lock:
            path = Path(path)
            if path in self._policy_paths:
                self._policy_paths.remove(path)
                self._file_mtimes.pop(str(path), None)
                return True
            return False

    def get_policy_paths(self) -> list[Path]:
        """Get the list of watched policy paths."""
        with self._lock:
            return self._policy_paths.copy()

    def on_reload(self, callback: ReloadCallback) -> None:
        """
        Register a callback for reload events.

        Args:
            callback: Function to call when a reload occurs.
        """
        with self._lock:
            self._reload_callbacks.append(callback)

    def remove_callback(self, callback: ReloadCallback) -> bool:
        """
        Remove a reload callback.

        Args:
            callback: The callback to remove.

        Returns:
            True if the callback was removed.
        """
        with self._lock:
            if callback in self._reload_callbacks:
                self._reload_callbacks.remove(callback)
                return True
            return False

    def start(self) -> None:
        """
        Start watching for file changes.

        If auto_reload is enabled, this starts a background thread
        that polls for file changes.
        """
        with self._lock:
            if self._watching:
                return

            # Initial load
            if self._policy_paths:
                self._load_policies(ReloadTrigger.STARTUP)

            if self._auto_reload:
                self._watching = True
                self._watch_thread = threading.Thread(
                    target=self._watch_loop,
                    daemon=True,
                    name="PolicyReloader-watch",
                )
                self._watch_thread.start()

    def stop(self) -> None:
        """Stop watching for file changes."""
        with self._lock:
            self._watching = False
            if self._watch_thread:
                self._watch_thread.join(timeout=self._poll_interval * 2)
                self._watch_thread = None

    def is_running(self) -> bool:
        """Check if the reloader is actively watching."""
        with self._lock:
            return self._watching

    def reload(self, user: str = "") -> ReloadEvent:
        """
        Manually trigger a policy reload.

        Args:
            user: Who triggered the reload.

        Returns:
            ReloadEvent describing the result.
        """
        return self._load_policies(ReloadTrigger.MANUAL, user=user)

    def reload_file(self, path: str | Path, user: str = "") -> ReloadEvent:
        """
        Reload a specific policy file.

        Args:
            path: Path to the policy file.
            user: Who triggered the reload.

        Returns:
            ReloadEvent describing the result.
        """
        path = Path(path)
        if path not in self._policy_paths:
            self.add_policy_path(path)
        return self._load_single_file(path, ReloadTrigger.MANUAL, user=user)

    def get_active_policy(self) -> PolicySet | None:
        """
        Get the currently active policy set.

        This is thread-safe and returns an atomic snapshot.

        Returns:
            The active PolicySet, or None if not loaded.
        """
        with self._policy_lock:
            return self._active_policy

    def get_version_manager(self) -> PolicyVersionManager:
        """Get the version manager for history and rollback."""
        return self._version_manager

    def get_active_version(self) -> PolicyVersion | None:
        """Get the currently active version."""
        return self._version_manager.get_active_version()

    def rollback(self, version: int, user: str = "") -> ReloadEvent:
        """
        Rollback to a previous policy version.

        Args:
            version: The version number to rollback to.
            user: Who triggered the rollback.

        Returns:
            ReloadEvent describing the result.
        """
        start_time = time.perf_counter()

        event = ReloadEvent(
            event_id=generate_uuid(),
            trigger=ReloadTrigger.ROLLBACK,
            timestamp=utc_now().isoformat(),
            success=False,
        )

        try:
            old_version = self._version_manager.get_version(version)
            if old_version is None:
                event.error = f"Version {version} not found"
                self._emit_event(event)
                return event

            # Rollback creates a new version
            policy_set = self._version_manager.rollback(version)

            # Atomic swap
            with self._policy_lock:
                self._active_policy = policy_set

            new_version = self._version_manager.get_active_version()
            event.success = True
            event.version = new_version.version_number if new_version else None
            event.policy_name = policy_set.name
            event.duration_ms = (time.perf_counter() - start_time) * 1000

        except Exception as e:
            event.error = str(e)

        self._emit_event(event)
        return event

    def get_events(self, limit: int = 50) -> list[ReloadEvent]:
        """
        Get recent reload events.

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of ReloadEvent objects, newest first.
        """
        with self._lock:
            return list(reversed(self._events[-limit:]))

    def _load_policies(self, trigger: ReloadTrigger, user: str = "") -> ReloadEvent:
        """
        Load policies from all configured paths.

        Args:
            trigger: How the reload was triggered.
            user: Who triggered the reload.

        Returns:
            ReloadEvent describing the result.
        """
        start_time = time.perf_counter()

        event = ReloadEvent(
            event_id=generate_uuid(),
            trigger=trigger,
            timestamp=utc_now().isoformat(),
            success=False,
            source_files=[str(p) for p in self._policy_paths],
        )

        if not self._policy_paths:
            event.error = "No policy paths configured"
            self._emit_event(event)
            return event

        # Load and merge all policy files
        merged_policy: PolicySet | None = None
        all_rules = []

        for path in self._policy_paths:
            try:
                if not path.exists():
                    event.error = f"Policy file not found: {path}"
                    self._emit_event(event)
                    return event

                result = self._parser.parse_file(path)
                if not result.success:
                    errors = "; ".join(str(e) for e in result.errors)
                    event.error = f"Parse error: {errors}"
                    self._emit_event(event)
                    return event

                if result.policy_set:
                    if merged_policy is None:
                        merged_policy = PolicySet(
                            name=result.policy_set.name,
                            version=result.policy_set.version,
                            description=result.policy_set.description,
                            metadata=result.policy_set.metadata.copy(),
                        )
                    all_rules.extend(result.policy_set.rules)

                # Update mtime tracking
                self._file_mtimes[str(path)] = path.stat().st_mtime

            except Exception as e:
                event.error = f"Failed to load {path}: {e}"
                self._emit_event(event)
                return event

        if merged_policy is None:
            event.error = "No policies loaded"
            self._emit_event(event)
            return event

        # Add all rules
        for rule in all_rules:
            merged_policy.add_rule(rule)

        # Validate if required
        if self._validate_before_reload:
            validation = self._validator.validate(merged_policy)
            event.validation_result = validation

            if not validation.valid:
                errors = "; ".join(m.message for m in validation.errors)
                event.error = f"Validation failed: {errors}"
                self._emit_event(event)
                return event

        # Create new version
        new_version = self._version_manager.create_version(
            policy_set=merged_policy,
            created_by=user or "system",
            commit_message=f"Reload triggered by {trigger.value}",
        )

        # Atomic swap
        with self._policy_lock:
            self._active_policy = merged_policy

        event.success = True
        event.version = new_version.version_number
        event.policy_name = merged_policy.name
        event.duration_ms = (time.perf_counter() - start_time) * 1000

        self._emit_event(event)
        return event

    def _load_single_file(
        self,
        path: Path,
        trigger: ReloadTrigger,
        user: str = "",
    ) -> ReloadEvent:
        """
        Load a single policy file.

        Args:
            path: Path to the policy file.
            trigger: How the reload was triggered.
            user: Who triggered the reload.

        Returns:
            ReloadEvent describing the result.
        """
        start_time = time.perf_counter()

        event = ReloadEvent(
            event_id=generate_uuid(),
            trigger=trigger,
            timestamp=utc_now().isoformat(),
            success=False,
            source_files=[str(path)],
        )

        try:
            if not path.exists():
                event.error = f"Policy file not found: {path}"
                self._emit_event(event)
                return event

            result = self._parser.parse_file(path)
            if not result.success:
                errors = "; ".join(str(e) for e in result.errors)
                event.error = f"Parse error: {errors}"
                self._emit_event(event)
                return event

            policy_set = result.policy_set
            if policy_set is None:
                event.error = "No policy loaded"
                self._emit_event(event)
                return event

            # Validate if required
            if self._validate_before_reload:
                validation = self._validator.validate(policy_set)
                event.validation_result = validation

                if not validation.valid:
                    errors = "; ".join(m.message for m in validation.errors)
                    event.error = f"Validation failed: {errors}"
                    self._emit_event(event)
                    return event

            # Create new version
            new_version = self._version_manager.create_version(
                policy_set=policy_set,
                created_by=user or "system",
                commit_message=f"Reload of {path.name} triggered by {trigger.value}",
            )

            # Atomic swap
            with self._policy_lock:
                self._active_policy = policy_set

            # Update mtime tracking
            self._file_mtimes[str(path)] = path.stat().st_mtime

            event.success = True
            event.version = new_version.version_number
            event.policy_name = policy_set.name
            event.duration_ms = (time.perf_counter() - start_time) * 1000

        except Exception as e:
            event.error = str(e)

        self._emit_event(event)
        return event

    def _watch_loop(self) -> None:
        """Background loop to watch for file changes."""
        while self._watching:
            try:
                self._check_for_changes()
            except Exception:
                # Silently continue watching even if check fails
                pass
            time.sleep(self._poll_interval)

    def _check_for_changes(self) -> None:
        """Check if any watched files have changed."""
        with self._lock:
            changed = False

            for path in self._policy_paths:
                path_str = str(path)
                if not path.exists():
                    continue

                current_mtime = path.stat().st_mtime
                if path_str in self._file_mtimes:
                    if current_mtime > self._file_mtimes[path_str]:
                        changed = True
                        break
                else:
                    # New file
                    self._file_mtimes[path_str] = current_mtime
                    changed = True
                    break

            if changed:
                self._load_policies(ReloadTrigger.FILE_CHANGE)

    def _emit_event(self, event: ReloadEvent) -> None:
        """Emit a reload event to all callbacks."""
        with self._lock:
            self._events.append(event)
            # Prune old events
            while len(self._events) > self._max_events:
                self._events.pop(0)

            callbacks = self._reload_callbacks.copy()

        # Call callbacks outside of lock
        for callback in callbacks:
            try:
                callback(event)
            except Exception:
                # Don't let callback errors break the reloader
                pass

    def set_parser(self, parser: PolicyParser) -> None:
        """
        Set a custom policy parser.

        Args:
            parser: The parser to use.
        """
        with self._lock:
            self._parser = parser

    def set_validator(self, validator: PolicyValidator) -> None:
        """
        Set a custom policy validator.

        Args:
            validator: The validator to use.
        """
        with self._lock:
            self._validator = validator

    def get_status(self) -> dict[str, Any]:
        """
        Get the current status of the reloader.

        Returns:
            Dictionary with status information.
        """
        active = self.get_active_policy()
        version = self.get_active_version()
        events = self.get_events(limit=5)

        return {
            "running": self.is_running(),
            "auto_reload": self._auto_reload,
            "poll_interval": self._poll_interval,
            "policy_paths": [str(p) for p in self._policy_paths],
            "active_policy": active.name if active else None,
            "active_version": version.version_number if version else None,
            "version_count": self._version_manager.get_version_count(),
            "recent_events": [e.to_dict() for e in events],
        }
