# PolicyBind Deployment Guide

This guide covers deploying PolicyBind in various configurations, from development to production.

## Deployment Modes

PolicyBind supports three deployment modes:

| Mode | Use Case | Latency | Complexity |
|------|----------|---------|------------|
| **Library** | Embedded in application | Lowest | Low |
| **Server** | Centralized enforcement | Low | Medium |
| **Hybrid** | Distributed with sync | Variable | High |

## Running as a Library

The simplest deployment embeds PolicyBind directly in your application.

### Installation

```bash
pip install policybind
```

### Basic Integration

```python
from policybind.engine.parser import PolicyParser
from policybind.engine.pipeline import EnforcementPipeline
from policybind.models.request import AIRequest
from policybind.storage import Database

# Initialize once at application startup
db = Database("policybind.db")
db.initialize()

parser = PolicyParser()
policy_set = parser.parse_file("policies/main.yaml")

pipeline = EnforcementPipeline(
    policy_set=policy_set,
    database=db,
)

# Call for each request
def enforce_ai_request(provider, model, user_id, department, **kwargs):
    request = AIRequest(
        provider=provider,
        model=model,
        user_id=user_id,
        department=department,
        **kwargs,
    )

    response = pipeline.enforce(request)

    if response.decision == "DENY":
        raise PermissionError(response.reason)

    return response
```

### Advantages

- No network latency
- No additional infrastructure
- Simple deployment
- Full control over lifecycle

### Considerations

- Policies must be distributed to each application instance
- Policy updates require application restart (unless using hot reload)
- Database must be accessible from each instance

## Running as a Server

For centralized enforcement, run PolicyBind as an HTTP server.

### Installation

```bash
pip install policybind[server]
```

### Starting the Server

```bash
# Basic start
policybind serve

# With configuration
policybind serve --config /etc/policybind/policybind.yaml

# With explicit host/port
policybind serve --host 0.0.0.0 --port 8080

# Background (production)
policybind serve --daemon --pid-file /var/run/policybind.pid
```

### Configuration

Create `/etc/policybind/policybind.yaml`:

```yaml
# Database configuration
database:
  path: /var/lib/policybind/policybind.db
  pool_size: 10
  timeout_seconds: 30

# Policy configuration
policies:
  path: /etc/policybind/policies/
  auto_reload: true
  reload_interval_seconds: 60

# Server configuration
server:
  host: 0.0.0.0
  port: 8080
  workers: 4
  cors_origins:
    - https://admin.example.com
  rate_limit_requests: 10000
  rate_limit_window_seconds: 60
  api_key_header: X-API-Key
  require_auth: true

# Logging configuration
logging:
  level: INFO
  format: json
  output_path: /var/log/policybind/policybind.log

# Metrics configuration
metrics:
  enabled: true
  port: 9090
```

### Environment Variables

Configuration can be overridden with environment variables:

```bash
export POLICYBIND_DATABASE_PATH=/var/lib/policybind/db.sqlite
export POLICYBIND_SERVER_PORT=8080
export POLICYBIND_LOGGING_LEVEL=DEBUG
```

### Systemd Service

Create `/etc/systemd/system/policybind.service`:

```ini
[Unit]
Description=PolicyBind AI Governance Server
After=network.target

[Service]
Type=simple
User=policybind
Group=policybind
WorkingDirectory=/var/lib/policybind
ExecStart=/usr/local/bin/policybind serve --config /etc/policybind/policybind.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/policybind /var/log/policybind

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable policybind
sudo systemctl start policybind
```

### Docker Deployment

#### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install PolicyBind
RUN pip install --no-cache-dir policybind[server]

# Create non-root user
RUN useradd -m -s /bin/bash policybind
USER policybind

# Create data directory
RUN mkdir -p /app/data /app/policies

# Copy policies
COPY --chown=policybind:policybind policies/ /app/policies/

# Copy configuration
COPY --chown=policybind:policybind policybind.yaml /app/

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/v1/health || exit 1

CMD ["policybind", "serve", "--config", "/app/policybind.yaml"]
```

#### Docker Compose

```yaml
version: '3.8'

services:
  policybind:
    build: .
    image: policybind:latest
    ports:
      - "8080:8080"
      - "9090:9090"  # Metrics
    volumes:
      - policybind-data:/app/data
      - ./policies:/app/policies:ro
    environment:
      - POLICYBIND_LOGGING_LEVEL=INFO
      - POLICYBIND_SERVER_WORKERS=4
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  policybind-data:
```

### Kubernetes Deployment

#### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: policybind
  labels:
    app: policybind
spec:
  replicas: 3
  selector:
    matchLabels:
      app: policybind
  template:
    metadata:
      labels:
        app: policybind
    spec:
      containers:
        - name: policybind
          image: policybind:latest
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 9090
              name: metrics
          env:
            - name: POLICYBIND_DATABASE_PATH
              value: /data/policybind.db
          volumeMounts:
            - name: data
              mountPath: /data
            - name: policies
              mountPath: /policies
              readOnly: true
            - name: config
              mountPath: /config
              readOnly: true
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /v1/health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /v1/ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: policybind-data
        - name: policies
          configMap:
            name: policybind-policies
        - name: config
          configMap:
            name: policybind-config
```

#### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: policybind
spec:
  selector:
    app: policybind
  ports:
    - name: http
      port: 80
      targetPort: 8080
    - name: metrics
      port: 9090
      targetPort: 9090
  type: ClusterIP
```

#### ConfigMap for Policies

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: policybind-policies
data:
  main.yaml: |
    name: production-policy
    version: "1.0.0"
    rules:
      - name: default-deny
        action: DENY
        priority: 0
```

## Production Considerations

### High Availability

For production deployments, ensure high availability:

1. **Multiple Replicas**: Run at least 3 replicas
2. **Load Balancing**: Use a load balancer for traffic distribution
3. **Health Checks**: Configure liveness and readiness probes
4. **Database**: Consider using PostgreSQL for multi-node deployments

### Database Options

#### SQLite (Default)

Suitable for:
- Single-node deployments
- Low to medium traffic
- Development/testing

Limitations:
- Single writer at a time
- Not suitable for multi-node

#### PostgreSQL (Coming Soon)

For production multi-node deployments:

```yaml
database:
  type: postgresql
  host: db.example.com
  port: 5432
  name: policybind
  user: policybind
  password_env: POLICYBIND_DB_PASSWORD
  pool_size: 20
```

### Scaling Guidance

| Requests/sec | Recommended Setup |
|--------------|-------------------|
| < 100 | Single node, SQLite |
| 100-1000 | 2-3 nodes, shared SQLite or PostgreSQL |
| 1000-10000 | 3-5 nodes, PostgreSQL, with caching |
| > 10000 | Multiple clusters, caching layer, read replicas |

### Caching

For high-traffic deployments, enable caching:

```yaml
cache:
  enabled: true
  type: memory  # or redis
  policy_ttl_seconds: 300
  token_ttl_seconds: 60

# With Redis
cache:
  enabled: true
  type: redis
  redis_url: redis://cache.example.com:6379
  policy_ttl_seconds: 300
```

### Performance Tuning

#### Worker Processes

```yaml
server:
  workers: 4  # Number of worker processes (typically 2-4 per CPU)
```

#### Connection Pooling

```yaml
database:
  pool_size: 20  # Connections per worker
  pool_overflow: 10  # Additional connections under load
```

#### Rate Limiting

```yaml
server:
  rate_limit_requests: 10000
  rate_limit_window_seconds: 60
  rate_limit_by: ip  # or api_key
```

## Monitoring and Observability

### Health Endpoints

- `GET /v1/health`: Basic health check
- `GET /v1/ready`: Readiness check (policies loaded, DB connected)

### Metrics Endpoint

Prometheus-format metrics at `GET /v1/metrics`:

```
# Enforcement metrics
policybind_requests_total{decision="ALLOW"} 15234
policybind_requests_total{decision="DENY"} 312
policybind_request_duration_seconds_bucket{le="0.001"} 8000

# Token metrics
policybind_active_tokens 42
policybind_token_validations_total 50000

# Registry metrics
policybind_registered_deployments 15
policybind_deployments_by_status{status="APPROVED"} 12
```

### Logging

Configure structured JSON logging for production:

```yaml
logging:
  level: INFO
  format: json
  output_path: /var/log/policybind/policybind.log
  include_request_id: true
  include_user_id: true
```

Example log entry:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "request_id": "req-abc123",
  "user_id": "user-001",
  "action": "enforce",
  "decision": "ALLOW",
  "model": "gpt-4",
  "latency_ms": 0.5,
  "applied_rules": ["allow-engineering"]
}
```

### Alerting

Recommended alerts:

| Alert | Condition | Severity |
|-------|-----------|----------|
| High Error Rate | > 1% of requests fail | Critical |
| High Latency | P99 > 100ms | Warning |
| Policy Load Failure | Policy reload fails | Critical |
| Database Connection | Connection failures | Critical |
| High Denial Rate | > 10% denials (unusual) | Warning |

### Tracing

Enable distributed tracing:

```yaml
tracing:
  enabled: true
  exporter: jaeger
  endpoint: http://jaeger:14268/api/traces
  sample_rate: 0.1  # 10% sampling
```

## Security Hardening

See [Security Guide](security.md) for detailed security configuration.

Key production security settings:

```yaml
server:
  require_auth: true
  tls_enabled: true
  tls_cert_file: /etc/policybind/tls/cert.pem
  tls_key_file: /etc/policybind/tls/key.pem

security:
  api_key_min_length: 32
  token_hash_algorithm: argon2
  audit_log_all: true
```

## Backup and Recovery

### Database Backup

For SQLite:

```bash
# Online backup
sqlite3 /var/lib/policybind/policybind.db ".backup /backup/policybind-$(date +%Y%m%d).db"

# With compression
sqlite3 /var/lib/policybind/policybind.db ".backup /dev/stdout" | gzip > /backup/policybind-$(date +%Y%m%d).db.gz
```

### Policy Backup

Store policies in version control:

```bash
# Policies should be in Git
git add policies/
git commit -m "Policy update: add new department rules"
git push
```

### Disaster Recovery

1. **Regular backups**: Daily database backups, retained for 30 days
2. **Geo-redundancy**: Replicate to another region
3. **Recovery testing**: Regularly test restoration
4. **Runbook**: Document recovery procedures

## Upgrading

### Rolling Update

For zero-downtime upgrades:

1. Deploy new version to subset of nodes
2. Verify health checks pass
3. Gradually shift traffic
4. Complete rollout

### Database Migrations

PolicyBind handles migrations automatically:

```bash
# Check current version
policybind status --show-schema-version

# Run migrations (automatic on startup)
policybind migrate

# Dry run
policybind migrate --dry-run
```

### Rollback

If issues occur:

```bash
# Rollback to previous policy version
policybind policy rollback v1.2.0

# Rollback application (Kubernetes)
kubectl rollout undo deployment/policybind
```
