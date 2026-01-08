"""
Database migration system for PolicyBind.

This module provides a simple migration system that can upgrade
the database schema between versions. Migrations are defined as
Python functions that receive a database connection.
"""

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from policybind.exceptions import StorageError
from policybind.storage.schema import SCHEMA_VERSION


@dataclass
class Migration:
    """
    Represents a database migration.

    Attributes:
        version: The schema version this migration upgrades to.
        description: Human-readable description of the migration.
        up: Function to apply the migration (upgrade).
        down: Optional function to reverse the migration (downgrade).
    """

    version: int
    description: str
    up: Callable[[sqlite3.Connection], None]
    down: Callable[[sqlite3.Connection], None] | None = None


class MigrationManager:
    """
    Manages database schema migrations.

    The migration manager tracks schema versions and applies
    migrations to upgrade the database to the current version.

    Example:
        Basic usage::

            from policybind.storage import Database, MigrationManager

            db = Database("policybind.db")
            migrator = MigrationManager(db)

            # Check and apply pending migrations
            migrator.migrate()
    """

    def __init__(self, db: "Database") -> None:  # type: ignore[name-defined]
        """
        Initialize the migration manager.

        Args:
            db: The Database instance to manage migrations for.
        """
        self.db = db
        self._migrations: list[Migration] = []
        self._register_migrations()

    def _register_migrations(self) -> None:
        """Register all available migrations."""
        # Migration 1: Initial schema (handled by schema.py)
        self._migrations.append(
            Migration(
                version=1,
                description="Initial schema",
                up=self._migration_v1_up,
                down=None,
            )
        )

        # Future migrations would be added here:
        # self._migrations.append(Migration(
        #     version=2,
        #     description="Add new column to policies",
        #     up=self._migration_v2_up,
        #     down=self._migration_v2_down,
        # ))

    def _migration_v1_up(self, conn: sqlite3.Connection) -> None:
        """
        Apply migration v1 - Initial schema.

        This migration is a no-op because the initial schema is
        applied during database initialization.
        """
        # Initial schema is applied by Database.initialize()
        pass

    def get_current_version(self) -> int:
        """
        Get the current schema version from the database.

        Returns:
            The current schema version, or 0 if no version is recorded.
        """
        try:
            result = self.db.execute_one(
                "SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1"
            )
            return result["version"] if result else 0
        except StorageError:
            return 0

    def get_target_version(self) -> int:
        """
        Get the target schema version.

        Returns:
            The schema version defined in schema.py.
        """
        return SCHEMA_VERSION

    def get_pending_migrations(self) -> list[Migration]:
        """
        Get list of migrations that need to be applied.

        Returns:
            List of Migration objects that haven't been applied yet.
        """
        current = self.get_current_version()
        return [m for m in self._migrations if m.version > current]

    def get_migration_history(self) -> list[dict]:
        """
        Get the migration history from the database.

        Returns:
            List of migration records with version, applied_at, and description.
        """
        try:
            return self.db.execute(
                "SELECT version, applied_at, description "
                "FROM schema_version ORDER BY applied_at"
            )
        except StorageError:
            return []

    def migrate(self, target_version: int | None = None) -> list[int]:
        """
        Apply pending migrations up to the target version.

        Args:
            target_version: The version to migrate to. If None, migrates
                to the latest version.

        Returns:
            List of migration versions that were applied.

        Raises:
            StorageError: If migration fails.
        """
        if target_version is None:
            target_version = self.get_target_version()

        current = self.get_current_version()
        applied: list[int] = []

        if current >= target_version:
            return applied

        pending = [m for m in self._migrations if current < m.version <= target_version]

        for migration in pending:
            try:
                self._apply_migration(migration)
                applied.append(migration.version)
            except Exception as e:
                raise StorageError(
                    f"Migration to v{migration.version} failed: {e}",
                    details={
                        "version": migration.version,
                        "description": migration.description,
                    },
                ) from e

        return applied

    def _apply_migration(self, migration: Migration) -> None:
        """
        Apply a single migration.

        Args:
            migration: The migration to apply.

        Raises:
            StorageError: If migration fails.
        """
        with self.db.transaction() as conn:
            # Apply the migration
            migration.up(conn)

            # Record the migration
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO schema_version (version, applied_at, description) "
                "VALUES (?, ?, ?)",
                (migration.version, now, migration.description),
            )

    def rollback(self, target_version: int) -> list[int]:
        """
        Rollback migrations to a target version.

        Args:
            target_version: The version to rollback to.

        Returns:
            List of migration versions that were rolled back.

        Raises:
            StorageError: If rollback fails or migration doesn't support rollback.
        """
        current = self.get_current_version()
        rolled_back: list[int] = []

        if current <= target_version:
            return rolled_back

        # Get migrations to rollback in reverse order
        to_rollback = [
            m for m in reversed(self._migrations) if target_version < m.version <= current
        ]

        for migration in to_rollback:
            if migration.down is None:
                raise StorageError(
                    f"Migration v{migration.version} does not support rollback",
                    details={
                        "version": migration.version,
                        "description": migration.description,
                    },
                )

            try:
                self._rollback_migration(migration)
                rolled_back.append(migration.version)
            except Exception as e:
                raise StorageError(
                    f"Rollback of v{migration.version} failed: {e}",
                    details={
                        "version": migration.version,
                        "description": migration.description,
                    },
                ) from e

        return rolled_back

    def _rollback_migration(self, migration: Migration) -> None:
        """
        Rollback a single migration.

        Args:
            migration: The migration to rollback.
        """
        if migration.down is None:
            raise StorageError(
                f"Migration v{migration.version} does not support rollback"
            )

        with self.db.transaction() as conn:
            # Apply the rollback
            migration.down(conn)

            # Remove the migration record
            conn.execute(
                "DELETE FROM schema_version WHERE version = ?", (migration.version,)
            )

    def check_schema(self) -> dict:
        """
        Check the current schema status.

        Returns:
            Dictionary with schema status information.
        """
        current = self.get_current_version()
        target = self.get_target_version()
        pending = self.get_pending_migrations()

        return {
            "current_version": current,
            "target_version": target,
            "is_current": current >= target,
            "pending_count": len(pending),
            "pending_versions": [m.version for m in pending],
        }

    def ensure_current(self) -> None:
        """
        Ensure the database schema is current.

        Applies any pending migrations if the schema is out of date.

        Raises:
            StorageError: If migrations fail.
        """
        status = self.check_schema()
        if not status["is_current"]:
            self.migrate()
