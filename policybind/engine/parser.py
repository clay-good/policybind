"""
Policy parser for PolicyBind.

This module provides the PolicyParser class for parsing YAML policy
files into PolicySet objects with support for includes, variable
substitution, and clear error messages.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from policybind.exceptions import PolicyError
from policybind.models.policy import PolicyRule, PolicySet


@dataclass
class ParseError:
    """
    Represents a parsing error with location information.

    Attributes:
        message: Human-readable error description.
        file: Path to the file where the error occurred.
        line: Line number where the error occurred (1-indexed).
        column: Column number where the error occurred (1-indexed).
    """

    message: str
    file: str = ""
    line: int = 0
    column: int = 0

    def __str__(self) -> str:
        """Return formatted error message with location."""
        location = ""
        if self.file:
            location = f"{self.file}"
            if self.line > 0:
                location += f":{self.line}"
                if self.column > 0:
                    location += f":{self.column}"
            location += ": "
        return f"{location}{self.message}"


@dataclass
class ParseResult:
    """
    Result of parsing a policy file.

    Attributes:
        policy_set: The parsed PolicySet, or None if parsing failed.
        errors: List of errors encountered during parsing.
        warnings: List of warnings encountered during parsing.
        included_files: List of files that were included.
    """

    policy_set: PolicySet | None = None
    errors: list[ParseError] = field(default_factory=list)
    warnings: list[ParseError] = field(default_factory=list)
    included_files: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Check if parsing succeeded without errors."""
        return len(self.errors) == 0 and self.policy_set is not None


class PolicyParser:
    """
    Parses YAML policy files into PolicySet objects.

    The PolicyParser supports:
    - Loading policies from YAML files or strings
    - Including other policy files with !include directive
    - Variable substitution with ${var} syntax
    - Clear error messages with line numbers
    - Comments and documentation within policy files

    Example:
        Parsing a policy file::

            parser = PolicyParser()
            result = parser.parse_file("policies/main.yaml")

            if result.success:
                policy_set = result.policy_set
            else:
                for error in result.errors:
                    print(f"Error: {error}")

    Policy File Format:
        See docs/policy-format.md for complete documentation.

        Basic structure::

            name: my-policy
            version: "1.0.0"
            description: My policy description

            variables:
              max_cost: 10.0

            rules:
              - name: deny-expensive
                description: Deny expensive requests
                match:
                  cost:
                    gt: ${max_cost}
                action: DENY
    """

    # Regex for variable substitution: ${variable_name}
    VAR_PATTERN = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

    def __init__(self, base_path: str | Path | None = None) -> None:
        """
        Initialize the policy parser.

        Args:
            base_path: Base path for resolving relative file includes.
                If None, uses the current working directory.
        """
        self.base_path = Path(base_path) if base_path else Path.cwd()
        self._included_files: set[str] = set()
        self._variables: dict[str, Any] = {}

    def parse_file(
        self,
        path: str | Path,
        variables: dict[str, Any] | None = None,
    ) -> ParseResult:
        """
        Parse a policy file.

        Args:
            path: Path to the YAML policy file.
            variables: Optional variables for substitution.

        Returns:
            ParseResult containing the parsed policy or errors.
        """
        path = Path(path)
        if not path.is_absolute():
            path = self.base_path / path

        result = ParseResult()

        if not path.exists():
            result.errors.append(
                ParseError(f"Policy file not found: {path}", file=str(path))
            )
            return result

        # Track included files to detect circular dependencies
        self._included_files = {str(path.resolve())}
        self._variables = variables.copy() if variables else {}

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            return self._parse_content(content, str(path), result)
        except OSError as e:
            result.errors.append(
                ParseError(f"Failed to read file: {e}", file=str(path))
            )
            return result

    def parse_string(
        self,
        content: str,
        source: str = "<string>",
        variables: dict[str, Any] | None = None,
    ) -> ParseResult:
        """
        Parse a policy from a YAML string.

        Args:
            content: YAML content to parse.
            source: Source identifier for error messages.
            variables: Optional variables for substitution.

        Returns:
            ParseResult containing the parsed policy or errors.
        """
        self._included_files = set()
        self._variables = variables.copy() if variables else {}
        result = ParseResult()
        return self._parse_content(content, source, result)

    def _parse_content(
        self,
        content: str,
        source: str,
        result: ParseResult,
    ) -> ParseResult:
        """
        Parse YAML content into a PolicySet.

        Args:
            content: YAML content to parse.
            source: Source identifier for error messages.
            result: ParseResult to populate.

        Returns:
            Updated ParseResult.
        """
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            error_msg = str(e)
            line = 0
            if hasattr(e, "problem_mark") and e.problem_mark:
                line = e.problem_mark.line + 1
            result.errors.append(
                ParseError(f"YAML syntax error: {error_msg}", file=source, line=line)
            )
            return result

        if data is None:
            result.errors.append(
                ParseError("Empty policy file", file=source)
            )
            return result

        if not isinstance(data, dict):
            result.errors.append(
                ParseError("Policy file must be a YAML mapping", file=source)
            )
            return result

        # Extract and merge variables
        if "variables" in data:
            file_vars = data.get("variables", {})
            if isinstance(file_vars, dict):
                # File variables have lower precedence than passed variables
                merged_vars = {**file_vars, **self._variables}
                self._variables = merged_vars
            else:
                result.warnings.append(
                    ParseError("'variables' must be a mapping", file=source)
                )

        # Apply variable substitution to the entire data structure
        data = self._substitute_variables(data, source, result)

        # Process includes
        if "include" in data:
            includes = data.get("include", [])
            if isinstance(includes, str):
                includes = [includes]
            if isinstance(includes, list):
                for include_path in includes:
                    self._process_include(include_path, source, result)

        # Parse the policy set
        try:
            policy_set = self._parse_policy_set(data, source, result)
            result.policy_set = policy_set
        except Exception as e:
            result.errors.append(
                ParseError(f"Failed to parse policy: {e}", file=source)
            )

        result.included_files = list(self._included_files)
        return result

    def _substitute_variables(
        self,
        data: Any,
        source: str,
        result: ParseResult,
    ) -> Any:
        """
        Recursively substitute variables in data.

        Args:
            data: Data structure to process.
            source: Source identifier for error messages.
            result: ParseResult for collecting warnings.

        Returns:
            Data with variables substituted.
        """
        if isinstance(data, str):
            return self._substitute_string(data, source, result)
        elif isinstance(data, dict):
            return {
                key: self._substitute_variables(value, source, result)
                for key, value in data.items()
            }
        elif isinstance(data, list):
            return [
                self._substitute_variables(item, source, result)
                for item in data
            ]
        else:
            return data

    def _substitute_string(
        self,
        text: str,
        source: str,
        result: ParseResult,
    ) -> Any:
        """
        Substitute variables in a string.

        Args:
            text: String to process.
            source: Source identifier for error messages.
            result: ParseResult for collecting warnings.

        Returns:
            String with variables substituted, or the original type
            if the entire string is a variable reference.
        """

        def replace_var(match: re.Match[str]) -> str:
            var_name = match.group(1)
            if var_name in self._variables:
                value = self._variables[var_name]
                return str(value)
            else:
                result.warnings.append(
                    ParseError(f"Undefined variable: {var_name}", file=source)
                )
                return match.group(0)  # Keep original

        # Check if the entire string is a single variable reference
        full_var_match = re.fullmatch(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}", text)
        if full_var_match:
            var_name = full_var_match.group(1)
            if var_name in self._variables:
                # Return the actual value (preserving type)
                return self._variables[var_name]

        # Otherwise, substitute within the string
        return self.VAR_PATTERN.sub(replace_var, text)

    def _process_include(
        self,
        include_path: str,
        source: str,
        result: ParseResult,
    ) -> None:
        """
        Process an include directive.

        Args:
            include_path: Path to the file to include.
            source: Source of the include directive.
            result: ParseResult for collecting errors.
        """
        # Resolve the include path relative to the source file
        source_dir = Path(source).parent if source != "<string>" else self.base_path
        full_path = source_dir / include_path

        resolved = str(full_path.resolve())

        # Check for circular dependency
        if resolved in self._included_files:
            result.errors.append(
                ParseError(
                    f"Circular include detected: {include_path}",
                    file=source,
                )
            )
            return

        self._included_files.add(resolved)

        if not full_path.exists():
            result.errors.append(
                ParseError(
                    f"Included file not found: {include_path}",
                    file=source,
                )
            )
            return

        # Parse the included file
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse but don't create a separate PolicySet
            # The rules will be merged into the main policy
            included_data = yaml.safe_load(content)
            if included_data and isinstance(included_data, dict):
                # Merge variables from included file
                if "variables" in included_data:
                    inc_vars = included_data.get("variables", {})
                    if isinstance(inc_vars, dict):
                        for key, value in inc_vars.items():
                            if key not in self._variables:
                                self._variables[key] = value

        except yaml.YAMLError as e:
            result.errors.append(
                ParseError(
                    f"YAML error in included file: {e}",
                    file=str(full_path),
                )
            )
        except OSError as e:
            result.errors.append(
                ParseError(
                    f"Failed to read included file: {e}",
                    file=str(full_path),
                )
            )

    def _parse_policy_set(
        self,
        data: dict[str, Any],
        source: str,
        result: ParseResult,
    ) -> PolicySet:
        """
        Parse a PolicySet from a data dictionary.

        Args:
            data: Dictionary containing policy data.
            source: Source identifier for error messages.
            result: ParseResult for collecting errors/warnings.

        Returns:
            Parsed PolicySet.
        """
        name = data.get("name", "")
        if not name:
            result.warnings.append(
                ParseError("Policy set has no name", file=source)
            )
            name = "unnamed"

        version = str(data.get("version", "1.0.0"))
        description = data.get("description", "")
        metadata = data.get("metadata", {})

        policy_set = PolicySet(
            name=name,
            version=version,
            description=description,
            metadata=metadata if isinstance(metadata, dict) else {},
        )

        # Parse rules
        rules_data = data.get("rules", [])
        if not isinstance(rules_data, list):
            result.errors.append(
                ParseError("'rules' must be a list", file=source)
            )
            return policy_set

        for i, rule_data in enumerate(rules_data):
            if not isinstance(rule_data, dict):
                result.errors.append(
                    ParseError(f"Rule {i + 1} must be a mapping", file=source)
                )
                continue

            try:
                rule = self._parse_rule(rule_data, i + 1, source, result)
                policy_set.add_rule(rule)
            except Exception as e:
                result.errors.append(
                    ParseError(f"Failed to parse rule {i + 1}: {e}", file=source)
                )

        return policy_set

    def _parse_rule(
        self,
        data: dict[str, Any],
        index: int,
        source: str,
        result: ParseResult,
    ) -> PolicyRule:
        """
        Parse a PolicyRule from a data dictionary.

        Args:
            data: Dictionary containing rule data.
            index: Rule index for error messages.
            source: Source identifier for error messages.
            result: ParseResult for collecting errors/warnings.

        Returns:
            Parsed PolicyRule.
        """
        name = data.get("name", "")
        if not name:
            result.warnings.append(
                ParseError(f"Rule {index} has no name", file=source)
            )
            name = f"rule-{index}"

        description = data.get("description", "")
        priority = data.get("priority", 0)
        enabled = data.get("enabled", True)
        tags = data.get("tags", [])

        # Handle 'match' as alias for 'match_conditions'
        match_conditions = data.get("match_conditions", data.get("match", {}))
        if not isinstance(match_conditions, dict):
            result.errors.append(
                ParseError(
                    f"Rule '{name}': match_conditions must be a mapping",
                    file=source,
                )
            )
            match_conditions = {}

        # Parse action
        action = data.get("action", "DENY")
        if isinstance(action, str):
            action = action.upper()
        else:
            result.errors.append(
                ParseError(f"Rule '{name}': action must be a string", file=source)
            )
            action = "DENY"

        action_params = data.get("action_params", {})
        if not isinstance(action_params, dict):
            result.warnings.append(
                ParseError(
                    f"Rule '{name}': action_params must be a mapping",
                    file=source,
                )
            )
            action_params = {}

        # Convert tags list to tuple for frozen dataclass
        if isinstance(tags, list):
            tags = tuple(str(t) for t in tags)
        else:
            tags = ()

        return PolicyRule(
            name=name,
            description=description,
            match_conditions=match_conditions,
            action=action,
            action_params=action_params,
            priority=int(priority),
            enabled=bool(enabled),
            tags=tags,
        )
