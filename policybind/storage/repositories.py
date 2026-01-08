"""
Repository classes for PolicyBind data access.

This module provides repository classes following the repository pattern
for CRUD operations on PolicyBind data models.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from policybind.exceptions import StorageError
from policybind.models.base import generate_uuid, utc_now
from policybind.storage.database import Database


class BaseRepository:
    """
    Base class for all repositories.

    Provides common functionality for database operations.
    """

    def __init__(self, db: Database) -> None:
        """
        Initialize the repository.

        Args:
            db: The Database instance to use for operations.
        """
        self.db = db

    def _serialize_json(self, value: Any) -> str | None:
        """Serialize a value to JSON string."""
        if value is None:
            return None
        return json.dumps(value)

    def _deserialize_json(self, value: str | None) -> Any:
        """Deserialize a JSON string to a Python object."""
        if value is None:
            return None
        return json.loads(value)

    def _format_datetime(self, dt: datetime | None) -> str | None:
        """Format a datetime to ISO string."""
        if dt is None:
            return None
        return dt.isoformat()

    def _parse_datetime(self, value: str | None) -> datetime | None:
        """Parse an ISO datetime string."""
        if value is None:
            return None
        return datetime.fromisoformat(value)


class PolicyRepository(BaseRepository):
    """
    Repository for policy operations.

    Provides CRUD operations for PolicySet objects with versioning support.
    """

    def create(
        self,
        name: str,
        version: str,
        content: dict[str, Any],
        description: str = "",
        created_by: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Create a new policy.

        Args:
            name: Unique name for the policy.
            version: Version string for the policy.
            content: Serialized PolicySet content.
            description: Optional description.
            created_by: User who created the policy.
            metadata: Optional metadata.

        Returns:
            The ID of the created policy.

        Raises:
            StorageError: If creation fails.
        """
        policy_id = generate_uuid()
        now = utc_now().isoformat()

        self.db.execute_insert(
            """
            INSERT INTO policies (id, name, version, description, content,
                                  is_active, created_at, updated_at, created_by, metadata)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
            """,
            (
                policy_id,
                name,
                version,
                description,
                self._serialize_json(content),
                now,
                now,
                created_by,
                self._serialize_json(metadata),
            ),
        )

        # Log the creation
        self._log_audit(policy_id, name, "CREATE", None, content, created_by)

        return policy_id

    def get_by_id(self, policy_id: str) -> dict[str, Any] | None:
        """
        Get a policy by ID.

        Args:
            policy_id: The policy ID.

        Returns:
            The policy data as a dictionary, or None if not found.
        """
        result = self.db.execute_one(
            "SELECT * FROM policies WHERE id = ?", (policy_id,)
        )
        return self._deserialize_policy(result) if result else None

    def get_by_name(self, name: str) -> dict[str, Any] | None:
        """
        Get a policy by name.

        Args:
            name: The policy name.

        Returns:
            The policy data as a dictionary, or None if not found.
        """
        result = self.db.execute_one(
            "SELECT * FROM policies WHERE name = ?", (name,)
        )
        return self._deserialize_policy(result) if result else None

    def get_active(self) -> list[dict[str, Any]]:
        """
        Get all active policies.

        Returns:
            List of active policy dictionaries.
        """
        results = self.db.execute(
            "SELECT * FROM policies WHERE is_active = 1 ORDER BY name"
        )
        return [self._deserialize_policy(r) for r in results]

    def list_all(
        self,
        include_inactive: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List all policies with pagination.

        Args:
            include_inactive: Whether to include inactive policies.
            limit: Maximum number of results.
            offset: Number of results to skip.

        Returns:
            List of policy dictionaries.
        """
        if include_inactive:
            results = self.db.execute(
                "SELECT * FROM policies ORDER BY name LIMIT ? OFFSET ?",
                (limit, offset),
            )
        else:
            results = self.db.execute(
                "SELECT * FROM policies WHERE is_active = 1 ORDER BY name LIMIT ? OFFSET ?",
                (limit, offset),
            )
        return [self._deserialize_policy(r) for r in results]

    def update(
        self,
        policy_id: str,
        content: dict[str, Any],
        version: str | None = None,
        description: str | None = None,
        updated_by: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """
        Update an existing policy.

        Args:
            policy_id: The policy ID to update.
            content: New policy content.
            version: New version string.
            description: New description.
            updated_by: User making the update.
            metadata: New metadata.

        Returns:
            True if updated, False if policy not found.
        """
        old_policy = self.get_by_id(policy_id)
        if not old_policy:
            return False

        now = utc_now().isoformat()
        updates = ["content = ?", "updated_at = ?"]
        params: list[Any] = [self._serialize_json(content), now]

        if version is not None:
            updates.append("version = ?")
            params.append(version)
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if metadata is not None:
            updates.append("metadata = ?")
            params.append(self._serialize_json(metadata))

        params.append(policy_id)

        rows = self.db.execute_write(
            f"UPDATE policies SET {', '.join(updates)} WHERE id = ?",
            tuple(params),
        )

        if rows > 0:
            self._log_audit(
                policy_id,
                old_policy["name"],
                "UPDATE",
                old_policy["content"],
                content,
                updated_by,
            )

        return rows > 0

    def delete(self, policy_id: str, deleted_by: str | None = None) -> bool:
        """
        Delete a policy.

        Args:
            policy_id: The policy ID to delete.
            deleted_by: User making the deletion.

        Returns:
            True if deleted, False if policy not found.
        """
        old_policy = self.get_by_id(policy_id)
        if not old_policy:
            return False

        rows = self.db.execute_write(
            "DELETE FROM policies WHERE id = ?", (policy_id,)
        )

        if rows > 0:
            self._log_audit(
                policy_id,
                old_policy["name"],
                "DELETE",
                old_policy["content"],
                None,
                deleted_by,
            )

        return rows > 0

    def activate(self, policy_id: str, activated_by: str | None = None) -> bool:
        """Activate a policy."""
        rows = self.db.execute_write(
            "UPDATE policies SET is_active = 1, updated_at = ? WHERE id = ?",
            (utc_now().isoformat(), policy_id),
        )
        if rows > 0:
            policy = self.get_by_id(policy_id)
            if policy:
                self._log_audit(
                    policy_id, policy["name"], "ACTIVATE", None, None, activated_by
                )
        return rows > 0

    def deactivate(self, policy_id: str, deactivated_by: str | None = None) -> bool:
        """Deactivate a policy."""
        rows = self.db.execute_write(
            "UPDATE policies SET is_active = 0, updated_at = ? WHERE id = ?",
            (utc_now().isoformat(), policy_id),
        )
        if rows > 0:
            policy = self.get_by_id(policy_id)
            if policy:
                self._log_audit(
                    policy_id, policy["name"], "DEACTIVATE", None, None, deactivated_by
                )
        return rows > 0

    def get_versions(self, name: str) -> list[dict[str, Any]]:
        """Get all versions of a policy from audit log."""
        return self.db.execute(
            """
            SELECT timestamp, action, user_id, old_value, new_value
            FROM policy_audit_log
            WHERE policy_name = ?
            ORDER BY timestamp DESC
            """,
            (name,),
        )

    def _log_audit(
        self,
        policy_id: str,
        policy_name: str,
        action: str,
        old_value: Any,
        new_value: Any,
        user_id: str | None,
    ) -> None:
        """Log a policy audit event."""
        self.db.execute_insert(
            """
            INSERT INTO policy_audit_log
                (policy_id, policy_name, action, timestamp, user_id, old_value, new_value)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                policy_id,
                policy_name,
                action,
                utc_now().isoformat(),
                user_id,
                self._serialize_json(old_value),
                self._serialize_json(new_value),
            ),
        )

    def _deserialize_policy(self, row: dict[str, Any]) -> dict[str, Any]:
        """Deserialize a policy row."""
        return {
            **row,
            "content": self._deserialize_json(row.get("content")),
            "metadata": self._deserialize_json(row.get("metadata")),
            "is_active": bool(row.get("is_active")),
        }


class RegistryRepository(BaseRepository):
    """
    Repository for model registry operations.

    Provides CRUD operations for ModelDeployment records.
    """

    def create(
        self,
        name: str,
        model_provider: str,
        model_name: str,
        owner: str,
        description: str = "",
        model_version: str = "",
        owner_contact: str = "",
        data_categories: list[str] | None = None,
        risk_level: str = "MEDIUM",
        approval_status: str = "PENDING",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Create a new model deployment.

        Returns:
            The deployment ID of the created record.
        """
        record_id = generate_uuid()
        deployment_id = generate_uuid()
        now = utc_now().isoformat()

        self.db.execute_insert(
            """
            INSERT INTO model_registry
                (id, deployment_id, name, description, model_provider, model_name,
                 model_version, owner, owner_contact, data_categories, risk_level,
                 approval_status, created_at, updated_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                deployment_id,
                name,
                description,
                model_provider,
                model_name,
                model_version,
                owner,
                owner_contact,
                self._serialize_json(data_categories or []),
                risk_level,
                approval_status,
                now,
                now,
                self._serialize_json(metadata),
            ),
        )

        return deployment_id

    def get_by_id(self, deployment_id: str) -> dict[str, Any] | None:
        """Get a deployment by ID."""
        result = self.db.execute_one(
            "SELECT * FROM model_registry WHERE deployment_id = ?", (deployment_id,)
        )
        return self._deserialize_deployment(result) if result else None

    def get_by_name(self, name: str) -> dict[str, Any] | None:
        """Get a deployment by name."""
        result = self.db.execute_one(
            "SELECT * FROM model_registry WHERE name = ?", (name,)
        )
        return self._deserialize_deployment(result) if result else None

    def list_all(
        self,
        status: str | None = None,
        risk_level: str | None = None,
        owner: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List deployments with optional filters."""
        conditions = []
        params: list[Any] = []

        if status:
            conditions.append("approval_status = ?")
            params.append(status)
        if risk_level:
            conditions.append("risk_level = ?")
            params.append(risk_level)
        if owner:
            conditions.append("owner = ?")
            params.append(owner)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])

        results = self.db.execute(
            f"SELECT * FROM model_registry {where} ORDER BY name LIMIT ? OFFSET ?",
            tuple(params),
        )
        return [self._deserialize_deployment(r) for r in results]

    def get_by_risk_level(self, risk_level: str) -> list[dict[str, Any]]:
        """Get all deployments with a specific risk level."""
        results = self.db.execute(
            "SELECT * FROM model_registry WHERE risk_level = ? ORDER BY name",
            (risk_level,),
        )
        return [self._deserialize_deployment(r) for r in results]

    def get_pending_approval(self) -> list[dict[str, Any]]:
        """Get all deployments pending approval."""
        results = self.db.execute(
            "SELECT * FROM model_registry WHERE approval_status = 'PENDING' ORDER BY created_at"
        )
        return [self._deserialize_deployment(r) for r in results]

    def get_needing_review(self) -> list[dict[str, Any]]:
        """Get all deployments needing review."""
        now = utc_now().isoformat()
        results = self.db.execute(
            """
            SELECT * FROM model_registry
            WHERE next_review_date IS NOT NULL AND next_review_date <= ?
            ORDER BY next_review_date
            """,
            (now,),
        )
        return [self._deserialize_deployment(r) for r in results]

    def update(
        self,
        deployment_id: str,
        **kwargs: Any,
    ) -> bool:
        """
        Update a deployment.

        Args:
            deployment_id: The deployment ID to update.
            **kwargs: Fields to update.

        Returns:
            True if updated, False if not found.
        """
        if not kwargs:
            return False

        updates = []
        params: list[Any] = []

        field_mapping = {
            "name": "name",
            "description": "description",
            "model_version": "model_version",
            "owner": "owner",
            "owner_contact": "owner_contact",
            "risk_level": "risk_level",
            "approval_status": "approval_status",
            "approval_ticket": "approval_ticket",
        }

        for key, column in field_mapping.items():
            if key in kwargs:
                updates.append(f"{column} = ?")
                params.append(kwargs[key])

        if "data_categories" in kwargs:
            updates.append("data_categories = ?")
            params.append(self._serialize_json(kwargs["data_categories"]))

        if "metadata" in kwargs:
            updates.append("metadata = ?")
            params.append(self._serialize_json(kwargs["metadata"]))

        for date_field in ["deployment_date", "last_review_date", "next_review_date"]:
            if date_field in kwargs:
                updates.append(f"{date_field} = ?")
                params.append(self._format_datetime(kwargs[date_field]))

        updates.append("updated_at = ?")
        params.append(utc_now().isoformat())
        params.append(deployment_id)

        rows = self.db.execute_write(
            f"UPDATE model_registry SET {', '.join(updates)} WHERE deployment_id = ?",
            tuple(params),
        )
        return rows > 0

    def update_status(
        self,
        deployment_id: str,
        status: str,
        ticket: str | None = None,
    ) -> bool:
        """Update the approval status of a deployment."""
        params: list[Any] = [status, utc_now().isoformat()]
        sql = "UPDATE model_registry SET approval_status = ?, updated_at = ?"

        if ticket:
            sql += ", approval_ticket = ?"
            params.append(ticket)

        if status == "APPROVED":
            sql += ", deployment_date = ?"
            params.append(utc_now().isoformat())

        sql += " WHERE deployment_id = ?"
        params.append(deployment_id)

        return self.db.execute_write(sql, tuple(params)) > 0

    def delete(self, deployment_id: str) -> bool:
        """Delete a deployment."""
        return (
            self.db.execute_write(
                "DELETE FROM model_registry WHERE deployment_id = ?", (deployment_id,)
            )
            > 0
        )

    def _deserialize_deployment(self, row: dict[str, Any]) -> dict[str, Any]:
        """Deserialize a deployment row."""
        return {
            **row,
            "data_categories": self._deserialize_json(row.get("data_categories")) or [],
            "metadata": self._deserialize_json(row.get("metadata")),
        }


class AuditRepository(BaseRepository):
    """
    Repository for audit logging operations.

    Provides write-only operations for enforcement logs and audit trails.
    """

    def log_enforcement(
        self,
        request_id: str,
        provider: str,
        model: str,
        user_id: str,
        department: str,
        decision: str,
        applied_rules: list[str],
        reason: str,
        prompt_hash: str = "",
        estimated_tokens: int = 0,
        estimated_cost: float = 0.0,
        source_application: str = "",
        data_classification: list[str] | None = None,
        intended_use_case: str = "",
        modifications: dict[str, Any] | None = None,
        enforcement_time_ms: float = 0.0,
        warnings: list[str] | None = None,
        deployment_id: str | None = None,
        request_metadata: dict[str, Any] | None = None,
        response_metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Log an enforcement decision.

        Returns:
            The ID of the log entry.
        """
        log_id = generate_uuid()

        self.db.execute_insert(
            """
            INSERT INTO enforcement_log
                (id, request_id, timestamp, provider, model, prompt_hash,
                 estimated_tokens, estimated_cost, source_application, user_id,
                 department, data_classification, intended_use_case, decision,
                 applied_rules, modifications, enforcement_time_ms, reason,
                 warnings, deployment_id, request_metadata, response_metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                log_id,
                request_id,
                utc_now().isoformat(),
                provider,
                model,
                prompt_hash,
                estimated_tokens,
                estimated_cost,
                source_application,
                user_id,
                department,
                self._serialize_json(data_classification),
                intended_use_case,
                decision,
                self._serialize_json(applied_rules),
                self._serialize_json(modifications),
                enforcement_time_ms,
                reason,
                self._serialize_json(warnings),
                deployment_id,
                self._serialize_json(request_metadata),
                self._serialize_json(response_metadata),
            ),
        )

        return log_id

    def query_enforcement_logs(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        user_id: str | None = None,
        department: str | None = None,
        decision: str | None = None,
        deployment_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query enforcement logs with filters."""
        conditions = []
        params: list[Any] = []

        if start_date:
            conditions.append("timestamp >= ?")
            params.append(start_date.isoformat())
        if end_date:
            conditions.append("timestamp <= ?")
            params.append(end_date.isoformat())
        if user_id:
            conditions.append("user_id = ?")
            params.append(user_id)
        if department:
            conditions.append("department = ?")
            params.append(department)
        if decision:
            conditions.append("decision = ?")
            params.append(decision)
        if deployment_id:
            conditions.append("deployment_id = ?")
            params.append(deployment_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])

        results = self.db.execute(
            f"""
            SELECT * FROM enforcement_log
            {where}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )

        return [self._deserialize_log(r) for r in results]

    def get_enforcement_stats(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> dict[str, Any]:
        """Get enforcement statistics for a period."""
        params = (start_date.isoformat(), end_date.isoformat())

        total = self.db.execute_one(
            """
            SELECT COUNT(*) as count FROM enforcement_log
            WHERE timestamp >= ? AND timestamp <= ?
            """,
            params,
        )

        by_decision = self.db.execute(
            """
            SELECT decision, COUNT(*) as count FROM enforcement_log
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY decision
            """,
            params,
        )

        return {
            "total_requests": total["count"] if total else 0,
            "by_decision": {r["decision"]: r["count"] for r in by_decision},
            "period_start": start_date.isoformat(),
            "period_end": end_date.isoformat(),
        }

    def _deserialize_log(self, row: dict[str, Any]) -> dict[str, Any]:
        """Deserialize an enforcement log row."""
        return {
            **row,
            "data_classification": self._deserialize_json(row.get("data_classification")),
            "applied_rules": self._deserialize_json(row.get("applied_rules")),
            "modifications": self._deserialize_json(row.get("modifications")),
            "warnings": self._deserialize_json(row.get("warnings")),
            "request_metadata": self._deserialize_json(row.get("request_metadata")),
            "response_metadata": self._deserialize_json(row.get("response_metadata")),
        }


class TokenRepository(BaseRepository):
    """
    Repository for access token operations.

    Provides CRUD operations for access tokens.
    """

    def create(
        self,
        token_hash: str,
        subject: str,
        permissions: dict[str, Any],
        issuer: str | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Create a new token record.

        Args:
            token_hash: SHA-256 hash of the token value.
            subject: Who/what the token is for.
            permissions: Token permissions structure.
            issuer: Who issued the token.
            expires_at: When the token expires.
            metadata: Optional metadata.

        Returns:
            The token ID.
        """
        record_id = generate_uuid()
        token_id = generate_uuid()
        now = utc_now().isoformat()

        self.db.execute_insert(
            """
            INSERT INTO tokens
                (id, token_id, token_hash, subject, issuer, issued_at,
                 expires_at, permissions, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                token_id,
                token_hash,
                subject,
                issuer,
                now,
                self._format_datetime(expires_at),
                self._serialize_json(permissions),
                self._serialize_json(metadata),
            ),
        )

        return token_id

    def get_by_id(self, token_id: str) -> dict[str, Any] | None:
        """Get a token by ID."""
        result = self.db.execute_one(
            "SELECT * FROM tokens WHERE token_id = ?", (token_id,)
        )
        return self._deserialize_token(result) if result else None

    def get_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        """Get a token by its hash."""
        result = self.db.execute_one(
            "SELECT * FROM tokens WHERE token_hash = ?", (token_hash,)
        )
        return self._deserialize_token(result) if result else None

    def list_by_subject(
        self,
        subject: str,
        include_expired: bool = False,
        include_revoked: bool = False,
    ) -> list[dict[str, Any]]:
        """List tokens for a subject."""
        conditions = ["subject = ?"]
        params: list[Any] = [subject]

        if not include_expired:
            conditions.append("(expires_at IS NULL OR expires_at > ?)")
            params.append(utc_now().isoformat())
        if not include_revoked:
            conditions.append("revoked_at IS NULL")

        results = self.db.execute(
            f"SELECT * FROM tokens WHERE {' AND '.join(conditions)} ORDER BY issued_at DESC",
            tuple(params),
        )
        return [self._deserialize_token(r) for r in results]

    def list_active(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        """List all active (non-revoked, non-expired) tokens."""
        now = utc_now().isoformat()
        results = self.db.execute(
            """
            SELECT * FROM tokens
            WHERE revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > ?)
            ORDER BY issued_at DESC
            LIMIT ? OFFSET ?
            """,
            (now, limit, offset),
        )
        return [self._deserialize_token(r) for r in results]

    def revoke(self, token_id: str, reason: str | None = None) -> bool:
        """Revoke a token."""
        now = utc_now().isoformat()
        return (
            self.db.execute_write(
                "UPDATE tokens SET revoked_at = ?, revoked_reason = ? WHERE token_id = ?",
                (now, reason, token_id),
            )
            > 0
        )

    def update_usage(self, token_id: str) -> bool:
        """Update token usage statistics."""
        now = utc_now().isoformat()
        return (
            self.db.execute_write(
                "UPDATE tokens SET last_used_at = ?, use_count = use_count + 1 WHERE token_id = ?",
                (now, token_id),
            )
            > 0
        )

    def is_valid(self, token_hash: str) -> bool:
        """Check if a token is valid (exists, not expired, not revoked)."""
        now = utc_now().isoformat()
        result = self.db.execute_one(
            """
            SELECT 1 FROM tokens
            WHERE token_hash = ?
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (token_hash, now),
        )
        return result is not None

    def delete(self, token_id: str) -> bool:
        """Delete a token."""
        return (
            self.db.execute_write("DELETE FROM tokens WHERE token_id = ?", (token_id,))
            > 0
        )

    def _deserialize_token(self, row: dict[str, Any]) -> dict[str, Any]:
        """Deserialize a token row."""
        return {
            **row,
            "permissions": self._deserialize_json(row.get("permissions")),
            "metadata": self._deserialize_json(row.get("metadata")),
        }


class IncidentRepository(BaseRepository):
    """
    Repository for incident management operations.

    Provides CRUD operations for incident records.
    """

    def create(
        self,
        title: str,
        incident_type: str,
        severity: str = "MEDIUM",
        description: str = "",
        source_request_id: str | None = None,
        deployment_id: str | None = None,
        evidence: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Create a new incident.

        Returns:
            The incident ID.
        """
        record_id = generate_uuid()
        incident_id = generate_uuid()
        now = utc_now().isoformat()

        self.db.execute_insert(
            """
            INSERT INTO incidents
                (id, incident_id, severity, status, incident_type, source_request_id,
                 deployment_id, title, description, evidence, tags, created_at,
                 updated_at, metadata)
            VALUES (?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                incident_id,
                severity,
                incident_type,
                source_request_id,
                deployment_id,
                title,
                description,
                self._serialize_json(evidence),
                self._serialize_json(tags or []),
                now,
                now,
                self._serialize_json(metadata),
            ),
        )

        # Log initial timeline entry
        self._add_timeline_entry(incident_id, "CREATED", None, "OPEN", None)

        return incident_id

    def get_by_id(self, incident_id: str) -> dict[str, Any] | None:
        """Get an incident by ID."""
        result = self.db.execute_one(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        )
        return self._deserialize_incident(result) if result else None

    def list_all(
        self,
        status: str | None = None,
        severity: str | None = None,
        incident_type: str | None = None,
        deployment_id: str | None = None,
        assignee: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List incidents with filters."""
        conditions = []
        params: list[Any] = []

        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if incident_type:
            conditions.append("incident_type = ?")
            params.append(incident_type)
        if deployment_id:
            conditions.append("deployment_id = ?")
            params.append(deployment_id)
        if assignee:
            conditions.append("assignee = ?")
            params.append(assignee)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])

        results = self.db.execute(
            f"""
            SELECT * FROM incidents
            {where}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )
        return [self._deserialize_incident(r) for r in results]

    def get_open(self) -> list[dict[str, Any]]:
        """Get all open incidents."""
        results = self.db.execute(
            "SELECT * FROM incidents WHERE status = 'OPEN' ORDER BY severity, created_at"
        )
        return [self._deserialize_incident(r) for r in results]

    def update_status(
        self,
        incident_id: str,
        status: str,
        actor: str | None = None,
    ) -> bool:
        """Update incident status."""
        old = self.get_by_id(incident_id)
        if not old:
            return False

        now = utc_now().isoformat()
        updates = ["status = ?", "updated_at = ?"]
        params: list[Any] = [status, now]

        if status == "RESOLVED":
            updates.append("resolved_at = ?")
            params.append(now)

        params.append(incident_id)

        rows = self.db.execute_write(
            f"UPDATE incidents SET {', '.join(updates)} WHERE incident_id = ?",
            tuple(params),
        )

        if rows > 0:
            self._add_timeline_entry(
                incident_id, "STATUS_CHANGE", old["status"], status, actor
            )

        return rows > 0

    def assign(
        self,
        incident_id: str,
        assignee: str,
        actor: str | None = None,
    ) -> bool:
        """Assign an incident to someone."""
        old = self.get_by_id(incident_id)
        if not old:
            return False

        rows = self.db.execute_write(
            "UPDATE incidents SET assignee = ?, updated_at = ? WHERE incident_id = ?",
            (assignee, utc_now().isoformat(), incident_id),
        )

        if rows > 0:
            self._add_timeline_entry(
                incident_id, "ASSIGNMENT", old.get("assignee"), assignee, actor
            )

        return rows > 0

    def add_comment(
        self,
        incident_id: str,
        author: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Add a comment to an incident."""
        comment_id = self.db.execute_insert(
            """
            INSERT INTO incident_comments
                (incident_id, author, content, created_at, metadata)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                author,
                content,
                utc_now().isoformat(),
                self._serialize_json(metadata),
            ),
        )

        self._add_timeline_entry(incident_id, "COMMENT", None, content[:100], author)

        return comment_id

    def get_comments(self, incident_id: str) -> list[dict[str, Any]]:
        """Get all comments for an incident."""
        return self.db.execute(
            "SELECT * FROM incident_comments WHERE incident_id = ? ORDER BY created_at",
            (incident_id,),
        )

    def get_timeline(self, incident_id: str) -> list[dict[str, Any]]:
        """Get the timeline for an incident."""
        return self.db.execute(
            "SELECT * FROM incident_timeline WHERE incident_id = ? ORDER BY timestamp",
            (incident_id,),
        )

    def update(
        self,
        incident_id: str,
        **kwargs: Any,
    ) -> bool:
        """Update incident fields."""
        if not kwargs:
            return False

        updates = []
        params: list[Any] = []

        simple_fields = ["title", "description", "resolution", "root_cause", "severity"]
        for field in simple_fields:
            if field in kwargs:
                updates.append(f"{field} = ?")
                params.append(kwargs[field])

        if "tags" in kwargs:
            updates.append("tags = ?")
            params.append(self._serialize_json(kwargs["tags"]))

        if "evidence" in kwargs:
            updates.append("evidence = ?")
            params.append(self._serialize_json(kwargs["evidence"]))

        if "metadata" in kwargs:
            updates.append("metadata = ?")
            params.append(self._serialize_json(kwargs["metadata"]))

        updates.append("updated_at = ?")
        params.append(utc_now().isoformat())
        params.append(incident_id)

        return (
            self.db.execute_write(
                f"UPDATE incidents SET {', '.join(updates)} WHERE incident_id = ?",
                tuple(params),
            )
            > 0
        )

    def delete(self, incident_id: str) -> bool:
        """Delete an incident and its related records."""
        with self.db.transaction() as conn:
            conn.execute(
                "DELETE FROM incident_comments WHERE incident_id = ?", (incident_id,)
            )
            conn.execute(
                "DELETE FROM incident_timeline WHERE incident_id = ?", (incident_id,)
            )
            cursor = conn.execute(
                "DELETE FROM incidents WHERE incident_id = ?", (incident_id,)
            )
            return cursor.rowcount > 0

    def _add_timeline_entry(
        self,
        incident_id: str,
        event_type: str,
        old_value: str | None,
        new_value: str | None,
        actor: str | None,
    ) -> None:
        """Add a timeline entry."""
        self.db.execute_insert(
            """
            INSERT INTO incident_timeline
                (incident_id, event_type, old_value, new_value, actor, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (incident_id, event_type, old_value, new_value, actor, utc_now().isoformat()),
        )

    def set_resolution(
        self,
        incident_id: str,
        resolution: str,
        root_cause: str | None = None,
    ) -> bool:
        """Set the resolution and root cause for an incident."""
        now = utc_now().isoformat()
        return (
            self.db.execute_write(
                """
                UPDATE incidents
                SET resolution = ?, root_cause = ?, updated_at = ?
                WHERE incident_id = ?
                """,
                (resolution, root_cause, now, incident_id),
            )
            > 0
        )

    def update_severity(
        self,
        incident_id: str,
        severity: str,
        actor: str | None = None,
    ) -> bool:
        """Update the severity of an incident."""
        old = self.get_by_id(incident_id)
        if not old:
            return False

        now = utc_now().isoformat()
        rows = self.db.execute_write(
            "UPDATE incidents SET severity = ?, updated_at = ? WHERE incident_id = ?",
            (severity, now, incident_id),
        )

        if rows > 0:
            self._add_timeline_entry(
                incident_id, "SEVERITY_CHANGE", old["severity"], severity, actor
            )

        return rows > 0

    def unassign(self, incident_id: str) -> bool:
        """Remove the assignee from an incident."""
        now = utc_now().isoformat()
        return (
            self.db.execute_write(
                "UPDATE incidents SET assignee = NULL, updated_at = ? WHERE incident_id = ?",
                (now, incident_id),
            )
            > 0
        )

    def link_incidents(self, incident_id: str, related_id: str) -> None:
        """Link two incidents as related."""
        # Store in metadata for now (could be a separate table)
        incident = self.get_by_id(incident_id)
        if incident:
            metadata = incident.get("metadata") or {}
            related = metadata.get("related_incidents", [])
            if related_id not in related:
                related.append(related_id)
                metadata["related_incidents"] = related
                self.update(incident_id, metadata=metadata)

        # Bidirectional link
        related_incident = self.get_by_id(related_id)
        if related_incident:
            metadata = related_incident.get("metadata") or {}
            related = metadata.get("related_incidents", [])
            if incident_id not in related:
                related.append(incident_id)
                metadata["related_incidents"] = related
                self.update(related_id, metadata=metadata)

    def get_related_incidents(self, incident_id: str) -> list[str]:
        """Get IDs of related incidents."""
        incident = self.get_by_id(incident_id)
        if not incident:
            return []
        metadata = incident.get("metadata") or {}
        return metadata.get("related_incidents", [])

    def get_metrics(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        deployment_id: str | None = None,
    ) -> dict[str, Any]:
        """Get aggregated metrics for incidents."""
        conditions = []
        params: list[Any] = []

        if since:
            conditions.append("created_at >= ?")
            params.append(since.isoformat())
        if until:
            conditions.append("created_at < ?")
            params.append(until.isoformat())
        if deployment_id:
            conditions.append("deployment_id = ?")
            params.append(deployment_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        # Get counts by status
        status_query = f"""
            SELECT status, COUNT(*) as count
            FROM incidents {where}
            GROUP BY status
        """
        status_results = self.db.execute(status_query, tuple(params))
        status_counts = {r["status"]: r["count"] for r in status_results}

        # Get counts by severity
        severity_query = f"""
            SELECT severity, COUNT(*) as count
            FROM incidents {where}
            GROUP BY severity
        """
        severity_results = self.db.execute(severity_query, tuple(params))
        severity_counts = {r["severity"]: r["count"] for r in severity_results}

        # Get counts by type
        type_query = f"""
            SELECT incident_type, COUNT(*) as count
            FROM incidents {where}
            GROUP BY incident_type
        """
        type_results = self.db.execute(type_query, tuple(params))
        type_counts = {r["incident_type"]: r["count"] for r in type_results}

        # Get counts by deployment
        if where:
            deployment_query = f"""
                SELECT deployment_id, COUNT(*) as count
                FROM incidents {where}
                AND deployment_id IS NOT NULL
                GROUP BY deployment_id
            """
        else:
            deployment_query = """
                SELECT deployment_id, COUNT(*) as count
                FROM incidents
                WHERE deployment_id IS NOT NULL
                GROUP BY deployment_id
            """
        deployment_results = self.db.execute(deployment_query, tuple(params))
        deployment_counts = {r["deployment_id"]: r["count"] for r in deployment_results}

        # Total count
        total = sum(status_counts.values())

        # Calculate MTTR (Mean Time To Resolve) for resolved incidents
        mttr_query = f"""
            SELECT AVG(
                (julianday(resolved_at) - julianday(created_at)) * 24
            ) as avg_hours
            FROM incidents {where}
            {"AND" if where else "WHERE"} resolved_at IS NOT NULL
        """
        mttr_result = self.db.execute_one(mttr_query, tuple(params))
        mttr_hours = mttr_result["avg_hours"] if mttr_result else None

        return {
            "total_count": total,
            "open_count": status_counts.get("OPEN", 0),
            "investigating_count": status_counts.get("INVESTIGATING", 0),
            "resolved_count": status_counts.get("RESOLVED", 0),
            "closed_count": status_counts.get("CLOSED", 0),
            "by_severity": severity_counts,
            "by_type": type_counts,
            "by_deployment": deployment_counts,
            "mttr_hours": mttr_hours,
            "mtta_hours": None,  # Would need assignment tracking
        }

    def get_trend(
        self,
        days: int = 30,
        deployment_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get incident trend data over time."""
        since = (utc_now() - timedelta(days=days)).isoformat()

        conditions = ["created_at >= ?"]
        params: list[Any] = [since]

        if deployment_id:
            conditions.append("deployment_id = ?")
            params.append(deployment_id)

        where = f"WHERE {' AND '.join(conditions)}"

        query = f"""
            SELECT
                date(created_at) as date,
                severity,
                COUNT(*) as count
            FROM incidents {where}
            GROUP BY date(created_at), severity
            ORDER BY date(created_at)
        """
        results = self.db.execute(query, tuple(params))

        # Organize by date
        trend: dict[str, dict[str, Any]] = {}
        for r in results:
            date_str = r["date"]
            if date_str not in trend:
                trend[date_str] = {
                    "date": date_str,
                    "total": 0,
                    "LOW": 0,
                    "MEDIUM": 0,
                    "HIGH": 0,
                    "CRITICAL": 0,
                }
            trend[date_str][r["severity"]] = r["count"]
            trend[date_str]["total"] += r["count"]

        return list(trend.values())

    def _deserialize_incident(self, row: dict[str, Any]) -> dict[str, Any]:
        """Deserialize an incident row."""
        return {
            **row,
            "evidence": self._deserialize_json(row.get("evidence")),
            "tags": self._deserialize_json(row.get("tags")) or [],
            "metadata": self._deserialize_json(row.get("metadata")),
        }
