"""
Base model class for PolicyBind data models.

This module provides a base class with common functionality shared by
all PolicyBind data models, including automatic ID generation,
timestamp management, and serialization methods.
"""

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, TypeVar

T = TypeVar("T", bound="BaseModel")


def generate_uuid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Return the current UTC datetime."""
    return datetime.now(timezone.utc)


def serialize_value(value: Any, exclude_none: bool = False) -> Any:
    """
    Serialize a single value to a JSON-compatible type.

    Args:
        value: Value to serialize.
        exclude_none: If True, exclude None values in nested dicts/lists.

    Returns:
        JSON-compatible representation of the value.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    elif isinstance(value, dict):
        result = {}
        for k, v in value.items():
            if exclude_none and v is None:
                continue
            result[k] = serialize_value(v, exclude_none)
        return result
    elif isinstance(value, (list, tuple)):
        return [serialize_value(item, exclude_none) for item in value]
    elif hasattr(value, "to_dict"):
        return value.to_dict(exclude_none)
    elif hasattr(value, "value"):
        # Handle enums
        return value.value
    return value


@dataclass
class BaseModel:
    """
    Base class for all PolicyBind data models.

    Provides common fields and functionality shared across all models:
    - Automatic UUID generation for the id field
    - Automatic timestamp management for created_at and updated_at
    - Serialization to dict and JSON formats

    Note: This class is NOT frozen. Subclasses that need immutability
    should use frozen=True and not inherit from BaseModel directly.
    Instead, they should use the standalone serialization functions.

    Attributes:
        id: Unique identifier for the model instance. Auto-generated UUID4 string
            if not provided. This should be treated as immutable after creation.
        created_at: Timestamp when the model instance was created. Automatically
            set to the current UTC time if not provided.
        updated_at: Timestamp when the model instance was last modified.
            Automatically set to the current UTC time if not provided. Should be
            updated whenever the model is modified.
    """

    id: str = field(default_factory=generate_uuid)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """
        Convert the model instance to a dictionary.

        Handles special types like datetime by converting them to ISO format
        strings. Nested dataclasses are also converted recursively.

        Args:
            exclude_none: If True, exclude keys with None values from the output.

        Returns:
            A dictionary representation of the model with all fields serialized
            to JSON-compatible types.
        """
        result = asdict(self)
        return {
            k: serialize_value(v, exclude_none)
            for k, v in result.items()
            if not (exclude_none and v is None)
        }

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """
        Convert the model instance to a JSON string.

        Args:
            indent: Number of spaces for indentation. If None, output is compact.
            exclude_none: If True, exclude keys with None values from the output.

        Returns:
            A JSON string representation of the model.
        """
        return json.dumps(self.to_dict(exclude_none), indent=indent)

    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        """
        Create a model instance from a dictionary.

        This is a basic implementation that subclasses may need to override
        to handle special types like datetime parsing or nested models.

        Args:
            data: Dictionary containing field values.

        Returns:
            A new instance of the model class.
        """
        return cls(**data)

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        class_name = self.__class__.__name__
        fields = ", ".join(f"{k}={v!r}" for k, v in self.to_dict().items())
        return f"{class_name}({fields})"


def model_to_dict(instance: Any, exclude_none: bool = False) -> dict[str, Any]:
    """
    Convert a dataclass instance to a dictionary.

    This is a standalone function for use with frozen dataclasses
    that cannot inherit from BaseModel.

    Args:
        instance: A dataclass instance to convert.
        exclude_none: If True, exclude keys with None values from the output.

    Returns:
        A dictionary representation of the instance with all fields serialized
        to JSON-compatible types.
    """
    result = asdict(instance)
    return {
        k: serialize_value(v, exclude_none)
        for k, v in result.items()
        if not (exclude_none and v is None)
    }


def model_to_json(
    instance: Any, indent: int | None = None, exclude_none: bool = False
) -> str:
    """
    Convert a dataclass instance to a JSON string.

    This is a standalone function for use with frozen dataclasses
    that cannot inherit from BaseModel.

    Args:
        instance: A dataclass instance to convert.
        indent: Number of spaces for indentation. If None, output is compact.
        exclude_none: If True, exclude keys with None values from the output.

    Returns:
        A JSON string representation of the instance.
    """
    return json.dumps(model_to_dict(instance, exclude_none), indent=indent)
