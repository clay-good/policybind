"""
Database connection and management for PolicyBind.

This module provides the Database class for managing SQLite database
connections with proper connection pooling, WAL mode, and thread safety.
"""

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from policybind.exceptions import StorageError


class Database:
    """
    SQLite database connection manager with connection pooling.

    Provides thread-safe database access with automatic connection
    management, WAL mode for better concurrent read performance,
    and parameterized query support to prevent SQL injection.

    Attributes:
        path: Path to the SQLite database file.
        pool_size: Maximum number of connections in the pool.
        timeout: Connection timeout in seconds.

    Example:
        Basic usage::

            db = Database("policybind.db")
            db.initialize()

            with db.connection() as conn:
                cursor = conn.execute("SELECT * FROM policies")
                rows = cursor.fetchall()
    """

    def __init__(
        self,
        path: str | Path = "policybind.db",
        pool_size: int = 5,
        timeout: float = 30.0,
    ) -> None:
        """
        Initialize the database manager.

        Args:
            path: Path to the SQLite database file. Use ":memory:" for
                an in-memory database (useful for testing).
            pool_size: Maximum number of connections to maintain in the pool.
            timeout: Timeout in seconds for acquiring a connection.
        """
        self.path = Path(path) if path != ":memory:" else path
        self.pool_size = pool_size
        self.timeout = timeout

        self._pool: list[sqlite3.Connection] = []
        self._pool_lock = threading.Lock()
        self._local = threading.local()
        self._initialized = False

    def initialize(self) -> None:
        """
        Initialize the database and apply schema.

        Creates the database file if it doesn't exist and applies
        the current schema. This should be called once at startup.

        Raises:
            StorageError: If initialization fails.
        """
        try:
            with self.connection() as conn:
                # Enable WAL mode for better concurrent reads
                conn.execute("PRAGMA journal_mode=WAL")
                # Enable foreign keys
                conn.execute("PRAGMA foreign_keys=ON")
                # Set busy timeout
                conn.execute(f"PRAGMA busy_timeout={int(self.timeout * 1000)}")

                # Import schema here to avoid circular imports
                from policybind.storage.schema import SCHEMA_SQL

                conn.executescript(SCHEMA_SQL)
                conn.commit()

            self._initialized = True
        except sqlite3.Error as e:
            raise StorageError(
                f"Failed to initialize database: {e}",
                details={"path": str(self.path)},
            ) from e

    def _create_connection(self) -> sqlite3.Connection:
        """
        Create a new database connection with proper settings.

        Returns:
            A configured SQLite connection.

        Raises:
            StorageError: If connection creation fails.
        """
        try:
            conn = sqlite3.connect(
                str(self.path) if isinstance(self.path, Path) else self.path,
                timeout=self.timeout,
                check_same_thread=False,
            )
            # Return rows as dictionaries
            conn.row_factory = sqlite3.Row
            # Enable foreign keys for this connection
            conn.execute("PRAGMA foreign_keys=ON")
            return conn
        except sqlite3.Error as e:
            raise StorageError(
                f"Failed to create database connection: {e}",
                details={"path": str(self.path)},
            ) from e

    def _get_connection(self) -> sqlite3.Connection:
        """
        Get a connection from the pool or create a new one.

        Returns:
            A database connection.
        """
        with self._pool_lock:
            if self._pool:
                return self._pool.pop()

        return self._create_connection()

    def _return_connection(self, conn: sqlite3.Connection) -> None:
        """
        Return a connection to the pool.

        Args:
            conn: The connection to return.
        """
        with self._pool_lock:
            if len(self._pool) < self.pool_size:
                self._pool.append(conn)
            else:
                conn.close()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """
        Get a database connection from the pool.

        This context manager provides a connection that will be
        automatically returned to the pool when the context exits.
        If an exception occurs, the transaction is rolled back.

        Yields:
            A database connection.

        Raises:
            StorageError: If connection acquisition fails.

        Example:
            Using the connection context manager::

                with db.connection() as conn:
                    conn.execute("INSERT INTO ...")
                    conn.commit()
        """
        conn = self._get_connection()
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            self._return_connection(conn)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """
        Get a connection with automatic commit on success.

        This context manager automatically commits the transaction
        if no exception occurs, or rolls back on error.

        Yields:
            A database connection.

        Example:
            Using the transaction context manager::

                with db.transaction() as conn:
                    conn.execute("INSERT INTO ...")
                    # Automatically committed on exit
        """
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._return_connection(conn)

    def execute(
        self,
        sql: str,
        params: tuple[Any, ...] | dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute a SQL query and return all results as dictionaries.

        Args:
            sql: The SQL query to execute. Must use parameterized placeholders.
            params: Query parameters as a tuple (for ? placeholders) or
                dict (for :name placeholders).

        Returns:
            List of result rows as dictionaries.

        Raises:
            StorageError: If query execution fails.

        Example:
            Executing a parameterized query::

                results = db.execute(
                    "SELECT * FROM policies WHERE name = ?",
                    ("my-policy",)
                )
        """
        try:
            with self.connection() as conn:
                if params:
                    cursor = conn.execute(sql, params)
                else:
                    cursor = conn.execute(sql)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as e:
            raise StorageError(
                f"Query execution failed: {e}",
                details={"sql": sql[:100]},
            ) from e

    def execute_one(
        self,
        sql: str,
        params: tuple[Any, ...] | dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """
        Execute a SQL query and return the first result.

        Args:
            sql: The SQL query to execute.
            params: Query parameters.

        Returns:
            The first result row as a dictionary, or None if no results.

        Raises:
            StorageError: If query execution fails.
        """
        results = self.execute(sql, params)
        return results[0] if results else None

    def execute_write(
        self,
        sql: str,
        params: tuple[Any, ...] | dict[str, Any] | None = None,
    ) -> int:
        """
        Execute a write query (INSERT, UPDATE, DELETE) and return affected rows.

        Args:
            sql: The SQL query to execute.
            params: Query parameters.

        Returns:
            Number of rows affected by the query.

        Raises:
            StorageError: If query execution fails.
        """
        try:
            with self.transaction() as conn:
                if params:
                    cursor = conn.execute(sql, params)
                else:
                    cursor = conn.execute(sql)
                return cursor.rowcount
        except sqlite3.Error as e:
            raise StorageError(
                f"Write query failed: {e}",
                details={"sql": sql[:100]},
            ) from e

    def execute_insert(
        self,
        sql: str,
        params: tuple[Any, ...] | dict[str, Any] | None = None,
    ) -> int:
        """
        Execute an INSERT query and return the last inserted row ID.

        Args:
            sql: The INSERT SQL query to execute.
            params: Query parameters.

        Returns:
            The row ID of the last inserted row.

        Raises:
            StorageError: If query execution fails.
        """
        try:
            with self.transaction() as conn:
                if params:
                    cursor = conn.execute(sql, params)
                else:
                    cursor = conn.execute(sql)
                return cursor.lastrowid or 0
        except sqlite3.Error as e:
            raise StorageError(
                f"Insert query failed: {e}",
                details={"sql": sql[:100]},
            ) from e

    def health_check(self) -> bool:
        """
        Check if the database is healthy and accessible.

        Returns:
            True if the database is accessible, False otherwise.
        """
        try:
            with self.connection() as conn:
                conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    def validate_connection(self) -> dict[str, Any]:
        """
        Validate the database connection and return diagnostic information.

        Returns:
            Dictionary containing database status information including
            path, WAL mode status, foreign keys status, and schema version.

        Raises:
            StorageError: If validation fails.
        """
        try:
            with self.connection() as conn:
                # Check WAL mode
                wal_result = conn.execute("PRAGMA journal_mode").fetchone()
                wal_mode = wal_result[0] if wal_result else "unknown"

                # Check foreign keys
                fk_result = conn.execute("PRAGMA foreign_keys").fetchone()
                foreign_keys = bool(fk_result[0]) if fk_result else False

                # Get schema version
                try:
                    version_result = conn.execute(
                        "SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1"
                    ).fetchone()
                    schema_version = version_result[0] if version_result else 0
                except sqlite3.OperationalError:
                    schema_version = 0

                # Count tables
                tables_result = conn.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
                ).fetchone()
                table_count = tables_result[0] if tables_result else 0

                return {
                    "path": str(self.path),
                    "initialized": self._initialized,
                    "healthy": True,
                    "wal_mode": wal_mode,
                    "foreign_keys_enabled": foreign_keys,
                    "schema_version": schema_version,
                    "table_count": table_count,
                    "pool_size": self.pool_size,
                    "pool_available": len(self._pool),
                }
        except sqlite3.Error as e:
            raise StorageError(
                f"Database validation failed: {e}",
                details={"path": str(self.path)},
            ) from e

    def get_schema_version(self) -> int:
        """
        Get the current schema version from the database.

        Returns:
            The current schema version number, or 0 if not initialized.
        """
        try:
            result = self.execute_one(
                "SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1"
            )
            return result["version"] if result else 0
        except StorageError:
            return 0

    def close(self) -> None:
        """
        Close all connections in the pool.

        Should be called when shutting down the application.
        """
        with self._pool_lock:
            for conn in self._pool:
                try:
                    conn.close()
                except Exception:
                    pass
            self._pool.clear()

    def __enter__(self) -> "Database":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit - close all connections."""
        self.close()

    def __repr__(self) -> str:
        """Return string representation."""
        return f"Database(path={self.path!r}, pool_size={self.pool_size})"
