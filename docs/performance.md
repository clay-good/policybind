# PolicyBind Performance Guide

This guide covers performance characteristics, tuning recommendations, and benchmarking methodology for PolicyBind.

## Performance Targets

PolicyBind is designed to meet the following performance targets:

| Metric | Target | Typical |
|--------|--------|---------|
| Matcher latency (P99) | < 1ms | 0.1-0.5ms |
| Pipeline latency (P99) | < 10ms | 1-5ms |
| Throughput (matcher) | > 50,000 req/s | 100,000+ req/s |
| Throughput (pipeline) | > 10,000 req/s | 20,000+ req/s |
| Memory per 1000 rules | < 10MB | 2-5MB |

These targets assume:
- Policy sets of up to 100 rules
- Standard hardware (4+ cores, 8GB+ RAM)
- SQLite database with WAL mode

## Performance Characteristics

### Policy Matching

Policy matching is the most performance-critical operation. Key factors affecting matching performance:

1. **Number of Rules**: Linear impact up to ~100 rules, then sub-linear due to optimizations
2. **Condition Complexity**: Simple equality checks are fastest; regex and nested conditions are slower
3. **Rule Priority Order**: Higher priority rules are checked first; frequently matching rules should have high priority

**Matching Performance by Rule Count:**

| Rules | Avg Latency | P99 Latency | Throughput |
|-------|-------------|-------------|------------|
| 10 | 0.02ms | 0.05ms | 500,000/s |
| 50 | 0.08ms | 0.15ms | 125,000/s |
| 100 | 0.15ms | 0.30ms | 65,000/s |
| 500 | 0.50ms | 1.00ms | 20,000/s |

### Enforcement Pipeline

The full enforcement pipeline includes:
- Request validation
- Classification checking
- Policy matching
- Action execution
- Audit logging

Each stage adds overhead:

| Stage | Typical Latency |
|-------|-----------------|
| Validation | 0.01-0.05ms |
| Classification | 0.01-0.02ms |
| Matching | 0.05-0.50ms |
| Action Execution | 0.01-0.10ms |
| Audit Logging | 0.10-1.00ms |

**Note:** Audit logging is the biggest variable - database writes can vary significantly based on load and disk performance.

### Token Validation

Token validation performance depends on caching:

| Scenario | Latency |
|----------|---------|
| Cached validation | 0.01-0.02ms |
| Database lookup | 0.5-2.0ms |
| Full validation (no cache) | 1.0-5.0ms |

Default cache TTL is 60 seconds, providing a good balance between performance and freshness.

## Caching

PolicyBind uses multiple levels of caching to optimize performance.

### Condition Cache

Compiled conditions are cached to avoid repeated parsing:

```python
# Conditions are automatically cached
matcher = PolicyMatcher()
matcher.precompile(policy_set)  # Compiles all conditions upfront
```

Cache characteristics:
- **TTL**: 1 hour (conditions rarely change)
- **Max size**: 1,000 entries
- **Invalidation**: On policy reload

### Token Validation Cache

Token permission checks are cached:

```python
validator = TokenValidator(
    token_manager,
    cache_ttl_seconds=60,  # Default: 60 seconds
    enable_cache=True,
)
```

Cache characteristics:
- **TTL**: 60 seconds (configurable)
- **Max size**: 10,000 entries
- **Invalidation**: On token revocation/expiration

**Important:** Token status (revoked/expired) is always checked fresh, even with caching enabled. Only permission validation is cached.

### Policy Match Cache

Optional caching for match results (useful for repeated identical requests):

```python
from policybind.cache import PolicyCache

cache = PolicyCache(
    match_ttl=60,      # Cache matches for 60 seconds
    max_matches=10000,
)
```

## Database Optimization

### SQLite Configuration

PolicyBind uses SQLite with the following optimizations:

1. **WAL Mode**: Enables concurrent reads during writes
2. **Connection Pooling**: Reuses connections to avoid overhead
3. **Prepared Statements**: Parameterized queries are pre-compiled

Configuration in `policybind.yaml`:

```yaml
database:
  path: /var/lib/policybind/policybind.db
  pool_size: 10
  timeout_seconds: 30
```

### Index Strategy

All tables have indexes on common query patterns:

**Enforcement Log Indexes:**
- `timestamp` - for time-range queries
- `user_id` - for user-specific queries
- `department` - for department queries
- `decision` - for filtering by decision type
- `deployment_id` - for deployment-specific queries

**Token Indexes:**
- `token_hash` - for token lookup
- `subject` - for subject queries
- `expires_at` - for expiration queries

### Query Optimization Tips

1. **Limit results**: Always use `LIMIT` for queries that could return many rows
2. **Use time bounds**: Include `timestamp` filters on enforcement_log queries
3. **Batch inserts**: Use transactions for multiple inserts
4. **Vacuum regularly**: Run `VACUUM` periodically to reclaim space

```bash
# Vacuum the database
sqlite3 /var/lib/policybind/policybind.db "VACUUM"

# Analyze for query optimization
sqlite3 /var/lib/policybind/policybind.db "ANALYZE"
```

## Tuning Recommendations

### For Low Latency

Minimize latency for real-time enforcement:

```yaml
# policybind.yaml
database:
  pool_size: 20        # More connections
  timeout_seconds: 5   # Shorter timeout

enforcement:
  log_all_requests: false  # Disable audit logging
```

```python
# Pipeline configuration
config = PipelineConfig(
    enable_timing=False,      # Disable timing instrumentation
    enable_audit=False,       # Disable audit logging
    rate_limit_enabled=False, # Disable rate limiting
)
```

### For High Throughput

Maximize requests per second:

```yaml
database:
  pool_size: 50           # Large pool for concurrency

server:
  workers: 8              # More worker processes
```

```python
# Use async pipeline for I/O-bound scenarios
from policybind.engine.pipeline import AsyncEnforcementPipeline

pipeline = AsyncEnforcementPipeline(policy_set)
response = await pipeline.process_async(request)
```

### For Memory Efficiency

Minimize memory footprint:

```yaml
database:
  pool_size: 5           # Smaller pool
```

```python
# Limit cache sizes
from policybind.cache import PolicyCache

cache = PolicyCache(
    max_conditions=100,  # Smaller condition cache
    max_matches=1000,    # Smaller match cache
)
```

## Benchmarking

### Running the Benchmark Script

PolicyBind includes a benchmark script for measuring performance:

```bash
# Basic benchmark
python examples/scripts/09_benchmark.py

# Custom parameters
python examples/scripts/09_benchmark.py \
    --requests 50000 \
    --rules 100 \
    --warmup 1000

# Test with varying rule counts
python examples/scripts/09_benchmark.py --vary-rules
```

### Benchmark Output

The benchmark reports:
- **Throughput**: Requests per second
- **Latency percentiles**: Min, Avg, P50, P95, P99, Max
- **Performance target checks**: Pass/fail against targets

Example output:
```
============================================================
Benchmark: PolicyMatcher (50 rules)
============================================================
Requests:      10,000
Duration:      0.08s
Throughput:    125,000 req/s

Latency (ms):
  Min:         0.005
  Avg:         0.008
  P50:         0.007
  P95:         0.012
  P99:         0.015
  Max:         0.150
============================================================
```

### Custom Benchmarks

Create custom benchmarks for your specific use case:

```python
import time
from policybind.engine.pipeline import EnforcementPipeline
from policybind.models.request import AIRequest

# Create pipeline
pipeline = EnforcementPipeline(policy_set)

# Measure latency
latencies = []
for request in requests:
    start = time.perf_counter()
    pipeline.process(request)
    latencies.append((time.perf_counter() - start) * 1000)

# Calculate statistics
import statistics
print(f"Avg: {statistics.mean(latencies):.3f}ms")
print(f"P99: {statistics.quantiles(latencies, n=100)[98]:.3f}ms")
```

## Monitoring

### Metrics to Track

Monitor these metrics in production:

1. **Enforcement Latency**
   - P50, P95, P99 latencies
   - Latency by stage (matching, logging, etc.)

2. **Throughput**
   - Requests per second
   - Requests per minute by decision type

3. **Cache Performance**
   - Hit rate
   - Eviction rate
   - Cache size

4. **Database Performance**
   - Query latency
   - Connection pool utilization
   - Database file size

### Prometheus Metrics

When running as a server, PolicyBind exposes Prometheus metrics:

```
# Enforcement metrics
policybind_enforcement_latency_seconds{quantile="0.99"} 0.005
policybind_enforcement_total{decision="ALLOW"} 15234
policybind_enforcement_total{decision="DENY"} 312

# Cache metrics
policybind_cache_hits_total{cache="conditions"} 50000
policybind_cache_misses_total{cache="conditions"} 100
policybind_cache_size{cache="conditions"} 50

# Database metrics
policybind_db_query_latency_seconds{query="enforcement_log_insert"} 0.001
policybind_db_pool_size 10
policybind_db_pool_active 3
```

### Alerting Thresholds

Recommended alert thresholds:

| Metric | Warning | Critical |
|--------|---------|----------|
| Enforcement P99 latency | > 10ms | > 50ms |
| Cache hit rate | < 80% | < 50% |
| Database query latency | > 10ms | > 100ms |
| Error rate | > 0.1% | > 1% |

## Scaling

### Horizontal Scaling

For high-volume deployments:

1. **Multiple Server Instances**
   - Run multiple PolicyBind servers behind a load balancer
   - Each instance maintains its own cache
   - Consider PostgreSQL for shared database (coming soon)

2. **Read Replicas**
   - Use SQLite read replicas for query-heavy workloads
   - Primary handles writes, replicas handle reads

3. **Caching Layer**
   - Add Redis for distributed caching
   - Reduces database load significantly

### Vertical Scaling

When to scale up vs. scale out:

| Scenario | Recommendation |
|----------|----------------|
| CPU bound (high throughput) | Scale out (more instances) |
| Memory bound (large caches) | Scale up (more RAM) |
| I/O bound (database) | Scale up (faster disk) or scale out |
| Latency sensitive | Scale up (faster CPU) |

## Best Practices

1. **Precompile Policies**: Call `matcher.precompile()` on startup
2. **Use High Priority Rules**: Put frequently-matching rules at high priority
3. **Simplify Conditions**: Prefer simple equality over regex when possible
4. **Enable Caching**: Use caching in production
5. **Monitor Performance**: Track latencies and throughput continuously
6. **Benchmark Changes**: Test policy changes for performance impact
7. **Right-size Caches**: Tune cache sizes based on your workload
8. **Regular Maintenance**: Vacuum database, clear old audit logs
