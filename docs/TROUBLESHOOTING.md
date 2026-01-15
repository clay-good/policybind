# PolicyBind Troubleshooting Guide

This guide covers common issues you may encounter when using PolicyBind and provides solutions.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Configuration Errors](#configuration-errors)
- [Policy Errors](#policy-errors)
- [Database Errors](#database-errors)
- [Token Errors](#token-errors)
- [Server Issues](#server-issues)
- [Performance Issues](#performance-issues)
- [Error Code Reference](#error-code-reference)

---

## Installation Issues

### Package installation fails

**Symptoms:**
```
ERROR: Could not find a version that satisfies the requirement policybind
```

**Solutions:**
1. Ensure you're using Python 3.10 or higher:
   ```bash
   python --version
   ```

2. Upgrade pip:
   ```bash
   pip install --upgrade pip
   ```

3. For development installation:
   ```bash
   pip install -e .
   ```

### Import errors after installation

**Symptoms:**
```
ModuleNotFoundError: No module named 'policybind'
```

**Solutions:**
1. Verify the package is installed:
   ```bash
   pip list | grep policybind
   ```

2. Check you're using the correct Python environment:
   ```bash
   which python
   pip show policybind
   ```

3. Reinstall the package:
   ```bash
   pip uninstall policybind
   pip install policybind
   ```

---

## Configuration Errors

### E1001 - Configuration file not found

**Symptoms:**
```
[E1001] Configuration file not found: /path/to/config.yaml
```

**Solutions:**
1. Check the file path is correct
2. Create a configuration file from the example:
   ```bash
   cp configs/policybind.example.yaml configs/policybind.yaml
   ```
3. Initialize a new configuration:
   ```bash
   policybind init --path ./my-project
   ```

### E1002 - Invalid YAML syntax in configuration

**Symptoms:**
```
[E1002] Invalid YAML syntax in configuration file
```

**Solutions:**
1. Validate your YAML syntax:
   ```bash
   python -c "import yaml; yaml.safe_load(open('config.yaml'))"
   ```
2. Common YAML mistakes:
   - Missing colons after keys
   - Incorrect indentation (use spaces, not tabs)
   - Unquoted special characters
   - Missing quotes around strings with colons

### E1003 - Missing required configuration

**Symptoms:**
```
[E1003] Missing required configuration option: database.path
```

**Solutions:**
1. Add the missing configuration option to your config file
2. Check the example configuration for required fields:
   ```bash
   cat configs/policybind.example.yaml
   ```
3. Set the value via environment variable:
   ```bash
   export POLICYBIND_DATABASE_PATH=/path/to/db.sqlite
   ```

### E1005 - Missing environment variable

**Symptoms:**
```
[E1005] Required environment variable not set: POLICYBIND_SECRET_KEY
```

**Solutions:**
1. Set the required environment variable:
   ```bash
   export POLICYBIND_SECRET_KEY="your-secret-key"
   ```
2. Add it to your shell profile or `.env` file
3. Use a configuration file instead of environment variables

---

## Policy Errors

### E2001 - Policy file not found

**Symptoms:**
```
[E2001] Policy file not found: /path/to/policy.yaml
```

**Solutions:**
1. Verify the policy file path
2. Check file permissions
3. Use absolute paths instead of relative paths

### E2002 - Invalid YAML syntax in policy

**Symptoms:**
```
[E2002] Invalid YAML syntax in policy file at line 15
```

**Solutions:**
1. Check the indicated line number for syntax errors
2. Validate the policy file:
   ```bash
   policybind policy validate /path/to/policy.yaml
   ```
3. Common issues:
   - Incorrect list formatting (use `- ` prefix)
   - Unbalanced quotes
   - Special characters needing quotes

### E2003 - Invalid policy syntax

**Symptoms:**
```
[E2003] Invalid policy syntax: unknown field 'acton' in rule 'my-rule'
```

**Solutions:**
1. Check for typos in field names (e.g., `acton` vs `action`)
2. Review the policy reference documentation:
   ```bash
   cat docs/policy-reference.md
   ```
3. Validate the policy:
   ```bash
   policybind policy validate policy.yaml --verbose
   ```

### E2004 - Unknown action type

**Symptoms:**
```
[E2004] Unknown action type: BLOCK
```

**Solutions:**
1. Use a valid action type:
   - ALLOW
   - DENY
   - MODIFY
   - REQUIRE_APPROVAL
   - RATE_LIMIT
   - AUDIT
   - REDIRECT

2. Check spelling and case (actions are case-sensitive)

### E2005 - Invalid condition in policy

**Symptoms:**
```
[E2005] Invalid condition: unknown operator 'contains_all'
```

**Solutions:**
1. Use valid condition operators:
   - `eq`, `ne` (equals, not equals)
   - `gt`, `gte`, `lt`, `lte` (comparisons)
   - `in`, `not_in` (list membership)
   - `contains`, `not_contains` (list contains)
   - `matches`, `pattern` (regex matching)
   - `exists`, `not_exists` (field existence)

2. Review the policy reference for condition syntax

### E2006 - Circular policy include

**Symptoms:**
```
[E2006] Circular include detected: a.yaml -> b.yaml -> a.yaml
```

**Solutions:**
1. Review your policy includes to remove the cycle
2. Reorganize policies to have a clear hierarchy
3. Extract common rules to a shared base file

### E2007 - Conflicting policy rules

**Symptoms:**
```
[E2007] Conflicting rules detected: 'allow-all' and 'deny-all' have same conditions
```

**Solutions:**
1. This is a warning - rules are evaluated by priority
2. Set explicit priorities to resolve conflicts:
   ```yaml
   rules:
     - name: allow-engineering
       priority: 100
       # ...
     - name: deny-default
       priority: 0
       # ...
   ```
3. Review and consolidate duplicate rules

---

## Database Errors

### E7001 - Database connection failed

**Symptoms:**
```
[E7001] Failed to connect to database: /path/to/db.sqlite
```

**Solutions:**
1. Check the database file path exists
2. Verify file permissions
3. Initialize the database:
   ```bash
   policybind init
   ```
4. Check disk space availability
5. For SQLite, ensure the parent directory exists

### E7002 - Database query error

**Symptoms:**
```
[E7002] Database query failed: table 'policies' does not exist
```

**Solutions:**
1. Initialize or migrate the database:
   ```bash
   policybind init
   ```
2. Check database schema version:
   ```bash
   policybind status --show-schema-version
   ```
3. Run migrations:
   ```bash
   policybind migrate
   ```

### E7003 - Database integrity error

**Symptoms:**
```
[E7003] Database integrity error: UNIQUE constraint failed
```

**Solutions:**
1. Check for duplicate entries
2. Verify your data doesn't violate constraints
3. If database is corrupted, restore from backup or reinitialize

### Database is locked

**Symptoms:**
```
sqlite3.OperationalError: database is locked
```

**Solutions:**
1. Ensure only one process is writing to the database
2. Increase the database timeout in configuration:
   ```yaml
   database:
     timeout_seconds: 30
   ```
3. For high concurrency, consider using WAL mode (enabled by default)
4. Check for zombie processes holding locks

---

## Token Errors

### E6001 - Token not found

**Symptoms:**
```
[E6001] Token not found: tok_abc123
```

**Solutions:**
1. Verify the token ID is correct:
   ```bash
   policybind token list
   ```
2. The token may have been revoked or deleted
3. Create a new token if needed

### E6002 - Token expired

**Symptoms:**
```
[E6002] Token has expired
```

**Solutions:**
1. Create a new token:
   ```bash
   policybind token create --subject "my-app" --expires 30
   ```
2. Use tokens with longer expiration for long-running services
3. Implement token renewal in your application

### E6004 - Token revoked

**Symptoms:**
```
[E6004] Token has been revoked
```

**Solutions:**
1. Contact the token administrator
2. Create a new token with appropriate permissions
3. Check why the token was revoked (security incident?)

### E6006 - Token budget exceeded

**Symptoms:**
```
[E6006] Token budget exceeded: $100.00 limit reached
```

**Solutions:**
1. Wait for budget period to reset
2. Request a budget increase from administrators
3. Create a new token with higher budget:
   ```bash
   policybind token create --budget 500 --budget-period monthly
   ```

### E6007 - Rate limit exceeded

**Symptoms:**
```
[E6007] Rate limit exceeded: 100 requests per minute
```

**Solutions:**
1. Reduce request frequency
2. Implement backoff in your client
3. Request a higher rate limit
4. Use batch operations where possible

---

## Server Issues

### Server fails to start

**Symptoms:**
```
Error: Address already in use: 0.0.0.0:8080
```

**Solutions:**
1. Use a different port:
   ```bash
   policybind serve --port 8081
   ```
2. Find and stop the process using the port:
   ```bash
   lsof -i :8080
   kill <PID>
   ```

### Health check failing

**Symptoms:**
```
GET /v1/health returns 503 Service Unavailable
```

**Solutions:**
1. Check database connectivity
2. Verify configuration is loaded
3. Check server logs for errors
4. Ensure policies are loaded:
   ```bash
   policybind policy show
   ```

### Authentication errors

**Symptoms:**
```
401 Unauthorized: Invalid API key
```

**Solutions:**
1. Verify the API key is correct
2. Check the header name (default: `X-API-Key`)
3. Ensure the API key hasn't been revoked
4. For token auth, verify the token is valid:
   ```bash
   policybind token validate <token>
   ```

### Request timeout

**Symptoms:**
```
504 Gateway Timeout
```

**Solutions:**
1. Check server load and resources
2. Increase timeout settings
3. Profile and optimize slow policies
4. Check database query performance

---

## Performance Issues

### Slow policy evaluation

**Symptoms:**
- Enforcement latency > 10ms
- High CPU usage during enforcement

**Solutions:**
1. Reduce policy complexity
2. Use specific conditions instead of regex where possible
3. Organize rules by priority (most common first)
4. Enable policy caching
5. Profile with verbose logging:
   ```bash
   policybind --verbose policy test policy.yaml --request request.json
   ```

### High memory usage

**Symptoms:**
- Memory usage grows over time
- Out of memory errors

**Solutions:**
1. Increase connection pool cleanup frequency
2. Limit audit log retention
3. Enable WAL mode for SQLite (default)
4. Monitor and set memory limits

### Database performance

**Symptoms:**
- Slow queries
- Database file growing large

**Solutions:**
1. Run database maintenance:
   ```bash
   sqlite3 policybind.db "VACUUM"
   sqlite3 policybind.db "ANALYZE"
   ```
2. Archive old audit logs
3. Add indexes for common queries (done by default)
4. Consider PostgreSQL for high-volume deployments

---

## Error Code Reference

| Code Range | Category | Description |
|------------|----------|-------------|
| E1xxx | Configuration | Configuration file and option errors |
| E2xxx | Policy | Policy parsing and validation errors |
| E3xxx | Validation | Request validation errors |
| E4xxx | Enforcement | Policy enforcement pipeline errors |
| E5xxx | Registry | Model registry operation errors |
| E6xxx | Token | Access token errors |
| E7xxx | Storage | Database and storage errors |
| E8xxx | Incident | Incident management errors |
| E9xxx | General | General/unknown errors |

### Getting More Help

1. **Enable verbose mode** for detailed error information:
   ```bash
   policybind --verbose <command>
   ```

2. **Check logs** for additional context:
   ```bash
   tail -f /var/log/policybind/policybind.log
   ```

3. **Validate your setup**:
   ```bash
   policybind status --detailed
   policybind config validate
   policybind policy validate <policy-file>
   ```

4. **Report a bug** if you've found a new issue:
   - Include error code and full error message
   - Include steps to reproduce
   - Include PolicyBind version (`policybind --version`)
   - Include Python version (`python --version`)
   - Include relevant configuration (without secrets)

---

## Common Scenarios

### First-time Setup

If you're setting up PolicyBind for the first time:

```bash
# Initialize the project
policybind init --path ./my-project

# Verify the setup
cd my-project
policybind status

# Load your first policy
policybind policy load examples/policies/basic.yaml

# Test enforcement
policybind policy test examples/policies/basic.yaml --request '{"provider": "openai", "model": "gpt-4"}'
```

### Migrating from Previous Version

If you're upgrading PolicyBind:

```bash
# Backup your database first
cp policybind.db policybind.db.backup

# Check current schema version
policybind status --show-schema-version

# Run migrations
policybind migrate --dry-run  # Preview changes
policybind migrate            # Apply changes

# Verify the upgrade
policybind status
```

### Recovering from Errors

If PolicyBind is in a bad state:

```bash
# Check system status
policybind status --detailed

# Validate configuration
policybind config validate

# Validate policies
policybind policy validate <policy-file>

# If database is corrupted, reinitialize
policybind init --force  # WARNING: This will reset the database
```
