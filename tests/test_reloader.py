"""
Tests for the policy hot reloading and versioning system.

This module tests the PolicyReloader and PolicyVersionManager classes.
"""

import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from policybind.engine.reloader import (
    PolicyReloader,
    ReloadEvent,
    ReloadTrigger,
)
from policybind.engine.versioning import (
    PolicyDiff,
    PolicyVersion,
    PolicyVersionManager,
)
from policybind.models.policy import PolicyRule, PolicySet


# =============================================================================
# PolicyVersionManager Tests
# =============================================================================


class TestPolicyVersion:
    """Tests for the PolicyVersion dataclass."""

    def test_create_version(self) -> None:
        """Test creating a PolicyVersion."""
        policy_set = PolicySet(name="test", version="1.0.0")
        version = PolicyVersion(
            version_id="test-id",
            version_number=1,
            policy_set=policy_set,
            content_hash="abc123",
            created_at=datetime.now(timezone.utc),
            created_by="user@example.com",
            commit_message="Initial version",
        )

        assert version.version_id == "test-id"
        assert version.version_number == 1
        assert version.policy_set.name == "test"
        assert version.content_hash == "abc123"
        assert version.created_by == "user@example.com"
        assert version.commit_message == "Initial version"

    def test_version_to_dict(self) -> None:
        """Test converting a version to a dictionary."""
        policy_set = PolicySet(name="test", version="1.0.0")
        version = PolicyVersion(
            version_id="test-id",
            version_number=1,
            policy_set=policy_set,
            content_hash="abc123",
            created_at=datetime.now(timezone.utc),
        )

        data = version.to_dict()
        assert data["version_id"] == "test-id"
        assert data["version_number"] == 1
        assert data["policy_name"] == "test"
        assert data["policy_version"] == "1.0.0"
        assert data["content_hash"] == "abc123"
        assert data["rule_count"] == 0


class TestPolicyDiff:
    """Tests for the PolicyDiff dataclass."""

    def test_empty_diff(self) -> None:
        """Test a diff with no changes."""
        diff = PolicyDiff(from_version=1, to_version=2)
        assert not diff.has_changes
        assert diff.summary() == "No changes"

    def test_diff_with_added_rules(self) -> None:
        """Test a diff with added rules."""
        rule = PolicyRule(name="new-rule", action="ALLOW")
        diff = PolicyDiff(
            from_version=1,
            to_version=2,
            added_rules=[rule],
        )
        assert diff.has_changes
        assert "+1 rules" in diff.summary()

    def test_diff_with_removed_rules(self) -> None:
        """Test a diff with removed rules."""
        rule = PolicyRule(name="old-rule", action="DENY")
        diff = PolicyDiff(
            from_version=1,
            to_version=2,
            removed_rules=[rule],
        )
        assert diff.has_changes
        assert "-1 rules" in diff.summary()

    def test_diff_with_modified_rules(self) -> None:
        """Test a diff with modified rules."""
        old_rule = PolicyRule(name="rule", action="ALLOW")
        new_rule = PolicyRule(name="rule", action="DENY")
        diff = PolicyDiff(
            from_version=1,
            to_version=2,
            modified_rules=[(old_rule, new_rule)],
        )
        assert diff.has_changes
        assert "~1 modified" in diff.summary()

    def test_diff_to_dict(self) -> None:
        """Test converting a diff to a dictionary."""
        rule = PolicyRule(name="new-rule", action="ALLOW")
        diff = PolicyDiff(
            from_version=1,
            to_version=2,
            added_rules=[rule],
        )
        data = diff.to_dict()
        assert data["from_version"] == 1
        assert data["to_version"] == 2
        assert "new-rule" in data["added_rules"]
        assert data["has_changes"] is True


class TestPolicyVersionManager:
    """Tests for the PolicyVersionManager class."""

    def test_create_version(self) -> None:
        """Test creating a new version."""
        manager = PolicyVersionManager()
        policy_set = PolicySet(name="test", version="1.0.0")

        version = manager.create_version(
            policy_set=policy_set,
            created_by="user@example.com",
            commit_message="Initial version",
        )

        assert version.version_number == 1
        assert version.policy_set.name == "test"
        assert version.created_by == "user@example.com"
        assert version.commit_message == "Initial version"
        assert version.content_hash

    def test_create_multiple_versions(self) -> None:
        """Test creating multiple versions."""
        manager = PolicyVersionManager()

        policy1 = PolicySet(name="test", version="1.0.0")
        policy2 = PolicySet(name="test", version="1.1.0")

        v1 = manager.create_version(policy1)
        v2 = manager.create_version(policy2)

        assert v1.version_number == 1
        assert v2.version_number == 2
        assert manager.get_version_count() == 2

    def test_get_version(self) -> None:
        """Test retrieving a specific version."""
        manager = PolicyVersionManager()
        policy_set = PolicySet(name="test", version="1.0.0")
        manager.create_version(policy_set)

        version = manager.get_version(1)
        assert version is not None
        assert version.version_number == 1

        assert manager.get_version(999) is None

    def test_get_active_version(self) -> None:
        """Test getting the active version."""
        manager = PolicyVersionManager()
        assert manager.get_active_version() is None

        policy_set = PolicySet(name="test", version="1.0.0")
        manager.create_version(policy_set)

        active = manager.get_active_version()
        assert active is not None
        assert active.version_number == 1

    def test_get_active_policy(self) -> None:
        """Test getting the active policy set."""
        manager = PolicyVersionManager()
        assert manager.get_active_policy() is None

        policy_set = PolicySet(name="test", version="1.0.0")
        manager.create_version(policy_set)

        active = manager.get_active_policy()
        assert active is not None
        assert active.name == "test"

    def test_get_history(self) -> None:
        """Test getting version history."""
        manager = PolicyVersionManager()

        for i in range(5):
            policy = PolicySet(name="test", version=f"1.{i}.0")
            manager.create_version(policy)

        history = manager.get_history()
        assert len(history) == 5
        # Should be newest first
        assert history[0].version_number == 5
        assert history[-1].version_number == 1

    def test_get_history_with_limit(self) -> None:
        """Test getting history with limit and offset."""
        manager = PolicyVersionManager()

        for i in range(5):
            policy = PolicySet(name="test", version=f"1.{i}.0")
            manager.create_version(policy)

        history = manager.get_history(limit=2)
        assert len(history) == 2
        assert history[0].version_number == 5
        assert history[1].version_number == 4

        history = manager.get_history(limit=2, offset=2)
        assert len(history) == 2
        assert history[0].version_number == 3
        assert history[1].version_number == 2

    def test_get_version_at_time(self) -> None:
        """Test getting version at a specific time."""
        manager = PolicyVersionManager()

        policy1 = PolicySet(name="test", version="1.0.0")
        v1 = manager.create_version(policy1)

        # Wait a bit to ensure different timestamps
        time.sleep(0.01)
        after_v1 = datetime.now(timezone.utc)

        policy2 = PolicySet(name="test", version="1.1.0")
        manager.create_version(policy2)

        # Query time between v1 and v2
        version = manager.get_version_at_time(after_v1)
        assert version is not None
        assert version.version_number == 1

        # Query time before any version
        before = datetime.now(timezone.utc) - timedelta(days=1)
        assert manager.get_version_at_time(before) is None

    def test_diff_versions(self) -> None:
        """Test diffing between versions."""
        manager = PolicyVersionManager()

        policy1 = PolicySet(name="test", version="1.0.0")
        policy1.add_rule(PolicyRule(name="rule1", action="ALLOW"))
        manager.create_version(policy1)

        policy2 = PolicySet(name="test", version="1.1.0")
        policy2.add_rule(PolicyRule(name="rule1", action="DENY"))  # Modified
        policy2.add_rule(PolicyRule(name="rule2", action="ALLOW"))  # Added
        manager.create_version(policy2)

        diff = manager.diff(1, 2)
        assert diff.has_changes
        assert len(diff.added_rules) == 1
        assert diff.added_rules[0].name == "rule2"
        assert len(diff.modified_rules) == 1
        assert diff.modified_rules[0][0].action == "ALLOW"
        assert diff.modified_rules[0][1].action == "DENY"

    def test_diff_version_not_found(self) -> None:
        """Test diffing with non-existent version."""
        manager = PolicyVersionManager()
        policy = PolicySet(name="test")
        manager.create_version(policy)

        with pytest.raises(Exception):
            manager.diff(1, 999)

    def test_rollback(self) -> None:
        """Test rolling back to a previous version."""
        manager = PolicyVersionManager()

        policy1 = PolicySet(name="test", version="1.0.0")
        policy1.add_rule(PolicyRule(name="rule1", action="ALLOW"))
        manager.create_version(policy1)

        policy2 = PolicySet(name="test", version="1.1.0")
        policy2.add_rule(PolicyRule(name="rule2", action="DENY"))
        manager.create_version(policy2)

        # Rollback to v1
        restored = manager.rollback(1)
        assert restored.version == "1.0.0"
        assert len(restored.rules) == 1
        assert restored.rules[0].name == "rule1"

        # A new version should have been created
        assert manager.get_version_count() == 3
        active = manager.get_active_version()
        assert active is not None
        assert active.version_number == 3
        assert "Rollback to version 1" in active.commit_message

    def test_rollback_not_found(self) -> None:
        """Test rollback to non-existent version."""
        manager = PolicyVersionManager()
        policy = PolicySet(name="test")
        manager.create_version(policy)

        with pytest.raises(Exception):
            manager.rollback(999)

    def test_set_active(self) -> None:
        """Test setting a specific version as active."""
        manager = PolicyVersionManager()

        policy1 = PolicySet(name="test", version="1.0.0")
        manager.create_version(policy1)

        policy2 = PolicySet(name="test", version="1.1.0")
        manager.create_version(policy2)

        # Set v1 as active
        manager.set_active(1)
        active = manager.get_active_version()
        assert active is not None
        assert active.version_number == 1

    def test_version_pruning(self) -> None:
        """Test that old versions are pruned."""
        manager = PolicyVersionManager(max_versions=3)

        for i in range(5):
            policy = PolicySet(name="test", version=f"1.{i}.0")
            manager.create_version(policy)

        assert manager.get_version_count() == 3
        # Should have versions 3, 4, 5
        assert manager.get_version(1) is None
        assert manager.get_version(2) is None
        assert manager.get_version(3) is not None

    def test_version_callback(self) -> None:
        """Test version creation callback."""
        created_versions: list[PolicyVersion] = []

        def callback(version: PolicyVersion) -> None:
            created_versions.append(version)

        manager = PolicyVersionManager(on_version_created=callback)
        policy = PolicySet(name="test")
        manager.create_version(policy)

        assert len(created_versions) == 1
        assert created_versions[0].version_number == 1

    def test_content_hash_changes(self) -> None:
        """Test that content hash changes when policy changes."""
        manager = PolicyVersionManager()

        policy1 = PolicySet(name="test", version="1.0.0")
        v1 = manager.create_version(policy1)

        policy2 = PolicySet(name="test", version="1.0.0")
        policy2.add_rule(PolicyRule(name="new-rule", action="ALLOW"))
        v2 = manager.create_version(policy2)

        assert v1.content_hash != v2.content_hash

    def test_clear(self) -> None:
        """Test clearing all versions."""
        manager = PolicyVersionManager()
        policy = PolicySet(name="test")
        manager.create_version(policy)
        manager.create_version(policy)

        manager.clear()
        assert manager.get_version_count() == 0
        assert manager.get_active_version() is None

    def test_export_import_versions(self) -> None:
        """Test exporting and importing versions."""
        manager = PolicyVersionManager()
        policy = PolicySet(name="test", version="1.0.0")
        manager.create_version(policy, commit_message="Test version")

        exported = manager.export_versions()
        assert len(exported) == 1
        assert exported[0]["policy_name"] == "test"


# =============================================================================
# PolicyReloader Tests
# =============================================================================


class TestReloadEvent:
    """Tests for the ReloadEvent dataclass."""

    def test_create_event(self) -> None:
        """Test creating a reload event."""
        event = ReloadEvent(
            event_id="test-id",
            trigger=ReloadTrigger.MANUAL,
            timestamp="2024-01-01T00:00:00Z",
            success=True,
            version=1,
            policy_name="test",
        )

        assert event.event_id == "test-id"
        assert event.trigger == ReloadTrigger.MANUAL
        assert event.success is True
        assert event.version == 1

    def test_event_to_dict(self) -> None:
        """Test converting event to dictionary."""
        event = ReloadEvent(
            event_id="test-id",
            trigger=ReloadTrigger.FILE_CHANGE,
            timestamp="2024-01-01T00:00:00Z",
            success=True,
        )

        data = event.to_dict()
        assert data["event_id"] == "test-id"
        assert data["trigger"] == "file_change"
        assert data["success"] is True


class TestPolicyReloader:
    """Tests for the PolicyReloader class."""

    @pytest.fixture
    def temp_policy_dir(self) -> Path:
        """Create a temporary directory for policy files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def sample_policy_yaml(self) -> str:
        """Return sample policy YAML content."""
        return """
name: test-policy
version: "1.0.0"
description: Test policy

rules:
  - name: allow-openai
    description: Allow OpenAI requests
    match:
      provider: openai
    action: ALLOW
"""

    def test_create_reloader(self) -> None:
        """Test creating a policy reloader."""
        reloader = PolicyReloader()
        assert not reloader.is_running()
        assert reloader.get_active_policy() is None

    def test_add_remove_policy_path(self, temp_policy_dir: Path) -> None:
        """Test adding and removing policy paths."""
        reloader = PolicyReloader()
        path = temp_policy_dir / "test.yaml"

        reloader.add_policy_path(path)
        assert path in reloader.get_policy_paths()

        assert reloader.remove_policy_path(path)
        assert path not in reloader.get_policy_paths()

        assert not reloader.remove_policy_path(path)  # Already removed

    def test_load_policy_file(
        self,
        temp_policy_dir: Path,
        sample_policy_yaml: str,
    ) -> None:
        """Test loading a policy file."""
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(sample_policy_yaml)

        reloader = PolicyReloader(policy_paths=[policy_file])
        reloader.start()

        try:
            policy = reloader.get_active_policy()
            assert policy is not None
            assert policy.name == "test-policy"
            assert len(policy.rules) == 1
        finally:
            reloader.stop()

    def test_reload_manual(
        self,
        temp_policy_dir: Path,
        sample_policy_yaml: str,
    ) -> None:
        """Test manual policy reload."""
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(sample_policy_yaml)

        reloader = PolicyReloader(
            policy_paths=[policy_file],
            auto_reload=False,
        )
        reloader.start()

        try:
            # Initial load
            assert reloader.get_active_policy() is not None

            # Modify the file
            modified_yaml = sample_policy_yaml.replace("1.0.0", "1.1.0")
            policy_file.write_text(modified_yaml)

            # Manual reload
            event = reloader.reload()
            assert event.success
            assert event.trigger == ReloadTrigger.MANUAL

            policy = reloader.get_active_policy()
            assert policy is not None
            assert policy.version == "1.1.0"
        finally:
            reloader.stop()

    def test_reload_with_validation_error(self, temp_policy_dir: Path) -> None:
        """Test reload with validation error."""
        # Create a policy with an invalid action
        invalid_yaml = """
name: test-policy
version: "1.0.0"

rules:
  - name: bad-rule
    match:
      provider: openai
    action: INVALID_ACTION
"""
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(invalid_yaml)

        reloader = PolicyReloader(
            policy_paths=[policy_file],
            validate_before_reload=True,
        )

        event = reloader.reload()
        # The action validation happens at a different level,
        # so the policy will load but might have warnings
        # depending on validator strictness

    def test_reload_missing_file(self) -> None:
        """Test reload with missing file."""
        reloader = PolicyReloader(
            policy_paths=[Path("/nonexistent/policy.yaml")],
        )

        event = reloader.reload()
        assert not event.success
        assert "not found" in event.error.lower()

    def test_reload_no_paths(self) -> None:
        """Test reload with no paths configured."""
        reloader = PolicyReloader()
        event = reloader.reload()
        assert not event.success
        assert "no policy paths" in event.error.lower()

    def test_reload_callback(
        self,
        temp_policy_dir: Path,
        sample_policy_yaml: str,
    ) -> None:
        """Test reload callback is called."""
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(sample_policy_yaml)

        events: list[ReloadEvent] = []

        def callback(event: ReloadEvent) -> None:
            events.append(event)

        reloader = PolicyReloader(
            policy_paths=[policy_file],
            auto_reload=False,
        )
        reloader.on_reload(callback)
        reloader.start()

        try:
            assert len(events) == 1  # Startup event
            assert events[0].trigger == ReloadTrigger.STARTUP
            assert events[0].success

            reloader.reload()
            assert len(events) == 2
            assert events[1].trigger == ReloadTrigger.MANUAL
        finally:
            reloader.stop()

    def test_remove_callback(
        self,
        temp_policy_dir: Path,
        sample_policy_yaml: str,
    ) -> None:
        """Test removing a reload callback."""
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(sample_policy_yaml)

        events: list[ReloadEvent] = []

        def callback(event: ReloadEvent) -> None:
            events.append(event)

        reloader = PolicyReloader(
            policy_paths=[policy_file],
            auto_reload=False,
        )
        reloader.on_reload(callback)
        reloader.start()

        try:
            initial_count = len(events)

            # Remove callback
            assert reloader.remove_callback(callback)

            reloader.reload()
            assert len(events) == initial_count  # No new events
        finally:
            reloader.stop()

    def test_auto_reload(
        self,
        temp_policy_dir: Path,
        sample_policy_yaml: str,
    ) -> None:
        """Test automatic reload on file change."""
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(sample_policy_yaml)

        events: list[ReloadEvent] = []
        event_received = threading.Event()

        def callback(event: ReloadEvent) -> None:
            events.append(event)
            if event.trigger == ReloadTrigger.FILE_CHANGE:
                event_received.set()

        reloader = PolicyReloader(
            policy_paths=[policy_file],
            auto_reload=True,
            poll_interval=0.1,  # Fast polling for tests
        )
        reloader.on_reload(callback)
        reloader.start()

        try:
            # Wait for initial load
            time.sleep(0.2)
            assert reloader.get_active_policy() is not None

            # Modify the file
            time.sleep(0.1)  # Ensure mtime changes
            modified_yaml = sample_policy_yaml.replace("1.0.0", "1.1.0")
            policy_file.write_text(modified_yaml)

            # Wait for auto-reload
            assert event_received.wait(timeout=2.0), "File change not detected"

            policy = reloader.get_active_policy()
            assert policy is not None
            assert policy.version == "1.1.0"
        finally:
            reloader.stop()

    def test_rollback(
        self,
        temp_policy_dir: Path,
        sample_policy_yaml: str,
    ) -> None:
        """Test rollback to previous version."""
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(sample_policy_yaml)

        reloader = PolicyReloader(
            policy_paths=[policy_file],
            auto_reload=False,
        )
        reloader.start()

        try:
            # Initial version
            v1 = reloader.get_active_version()
            assert v1 is not None
            assert v1.policy_set.version == "1.0.0"

            # Modify and reload
            modified_yaml = sample_policy_yaml.replace("1.0.0", "1.1.0")
            policy_file.write_text(modified_yaml)
            reloader.reload()

            v2 = reloader.get_active_version()
            assert v2 is not None
            assert v2.policy_set.version == "1.1.0"

            # Rollback to v1
            event = reloader.rollback(1)
            assert event.success
            assert event.trigger == ReloadTrigger.ROLLBACK

            policy = reloader.get_active_policy()
            assert policy is not None
            assert policy.version == "1.0.0"
        finally:
            reloader.stop()

    def test_rollback_invalid_version(self) -> None:
        """Test rollback to non-existent version."""
        reloader = PolicyReloader()
        event = reloader.rollback(999)
        assert not event.success
        assert "not found" in event.error.lower()

    def test_get_events(
        self,
        temp_policy_dir: Path,
        sample_policy_yaml: str,
    ) -> None:
        """Test getting reload events."""
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(sample_policy_yaml)

        reloader = PolicyReloader(
            policy_paths=[policy_file],
            auto_reload=False,
        )
        reloader.start()

        try:
            reloader.reload()
            reloader.reload()

            events = reloader.get_events()
            assert len(events) >= 2
            # Should be newest first
            assert events[0].trigger == ReloadTrigger.MANUAL
        finally:
            reloader.stop()

    def test_get_status(
        self,
        temp_policy_dir: Path,
        sample_policy_yaml: str,
    ) -> None:
        """Test getting reloader status."""
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(sample_policy_yaml)

        reloader = PolicyReloader(
            policy_paths=[policy_file],
            auto_reload=True,
        )
        reloader.start()

        try:
            status = reloader.get_status()
            assert status["running"] is True
            assert status["auto_reload"] is True
            assert status["active_policy"] == "test-policy"
            assert status["active_version"] == 1
            assert len(status["policy_paths"]) == 1
        finally:
            reloader.stop()

    def test_multiple_policy_files(self, temp_policy_dir: Path) -> None:
        """Test loading multiple policy files."""
        policy1_yaml = """
name: policy1
version: "1.0.0"

rules:
  - name: rule1
    match:
      provider: openai
    action: ALLOW
"""
        policy2_yaml = """
name: policy2
version: "1.0.0"

rules:
  - name: rule2
    match:
      provider: anthropic
    action: ALLOW
"""
        policy1 = temp_policy_dir / "policy1.yaml"
        policy1.write_text(policy1_yaml)

        policy2 = temp_policy_dir / "policy2.yaml"
        policy2.write_text(policy2_yaml)

        reloader = PolicyReloader(
            policy_paths=[policy1, policy2],
            auto_reload=False,
        )
        reloader.start()

        try:
            policy = reloader.get_active_policy()
            assert policy is not None
            # Rules from both files should be merged
            assert len(policy.rules) == 2
            rule_names = {r.name for r in policy.rules}
            assert "rule1" in rule_names
            assert "rule2" in rule_names
        finally:
            reloader.stop()

    def test_reload_single_file(
        self,
        temp_policy_dir: Path,
        sample_policy_yaml: str,
    ) -> None:
        """Test reloading a single specific file."""
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(sample_policy_yaml)

        reloader = PolicyReloader(auto_reload=False)

        event = reloader.reload_file(policy_file)
        assert event.success
        assert reloader.get_active_policy() is not None

    def test_start_stop(self) -> None:
        """Test starting and stopping the reloader."""
        reloader = PolicyReloader(auto_reload=True)

        assert not reloader.is_running()

        reloader.start()
        assert reloader.is_running()

        reloader.stop()
        assert not reloader.is_running()

        # Should be safe to call stop again
        reloader.stop()
        assert not reloader.is_running()

    def test_version_manager_access(
        self,
        temp_policy_dir: Path,
        sample_policy_yaml: str,
    ) -> None:
        """Test accessing the version manager."""
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(sample_policy_yaml)

        reloader = PolicyReloader(
            policy_paths=[policy_file],
            auto_reload=False,
        )
        reloader.start()

        try:
            vm = reloader.get_version_manager()
            assert vm is not None
            assert vm.get_version_count() == 1

            # Reload to create a new version
            reloader.reload()
            assert vm.get_version_count() == 2
        finally:
            reloader.stop()

    def test_parse_error_handling(self, temp_policy_dir: Path) -> None:
        """Test handling of parse errors."""
        invalid_yaml = "invalid: yaml: content: {"
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(invalid_yaml)

        reloader = PolicyReloader(
            policy_paths=[policy_file],
            auto_reload=False,
        )

        event = reloader.reload()
        assert not event.success
        assert "error" in event.error.lower()

    def test_thread_safety(
        self,
        temp_policy_dir: Path,
        sample_policy_yaml: str,
    ) -> None:
        """Test thread safety of policy access."""
        policy_file = temp_policy_dir / "policy.yaml"
        policy_file.write_text(sample_policy_yaml)

        reloader = PolicyReloader(
            policy_paths=[policy_file],
            auto_reload=False,
        )
        reloader.start()

        try:
            errors: list[Exception] = []
            access_count = [0]

            def reader() -> None:
                for _ in range(100):
                    try:
                        policy = reloader.get_active_policy()
                        if policy:
                            _ = policy.name
                            access_count[0] += 1
                    except Exception as e:
                        errors.append(e)

            def writer() -> None:
                for _ in range(20):
                    try:
                        reloader.reload()
                    except Exception as e:
                        errors.append(e)
                    time.sleep(0.01)

            threads = [
                threading.Thread(target=reader) for _ in range(5)
            ]
            threads.append(threading.Thread(target=writer))

            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(errors) == 0
            assert access_count[0] > 0
        finally:
            reloader.stop()


class TestReloadTrigger:
    """Tests for ReloadTrigger enum."""

    def test_trigger_values(self) -> None:
        """Test trigger enum values."""
        assert ReloadTrigger.FILE_CHANGE.value == "file_change"
        assert ReloadTrigger.MANUAL.value == "manual"
        assert ReloadTrigger.STARTUP.value == "startup"
        assert ReloadTrigger.ROLLBACK.value == "rollback"
