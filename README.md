# 🐍 Python FastAPI Production Guide for Node.js Developers — FAANG-Level

> 🚀 **A comprehensive guide for Node.js developers transitioning to Python FastAPI with production-ready patterns and FAANG-level best practices.**

## 📋 Table of Contents

1. [Node.js → Python Mapping](#1--original-nodejs--python-mapping-notes)
2. [Project Structure](#2--python-best-practice-project-structure)
3. [Package Management](#3--package--dependency-management)
4. [Configuration](#4--environment--configuration)
5. [Running & Deployment](#5--running--deployment)
6. [Observability](#6--observability)
7. [Health & Resilience](#7--health-checks--graceful-shutdown)
8. [Security](#8--security-best-practices)
9. [Scalability](#9--scalability--reliability)
10. [CI/CD](#10--cicd-pipeline-example-github-actions)
11. [Testing](#11--testing-strategy)
12. [Final Checklist](#12--final-faang-level-checklist)
13. [Python Crash Course](#13--python-crash-course-for-nodejs-developers)

---

## 1. 🔄 Original Node.js → Python Mapping Notes

### 📦 **Packages & Modules**

- **Node.js**: `npm`, `package.json`, `node_modules`
- **Python**: `pip`, `requirements.txt` or `pyproject.toml`, `venv`
- 💡 **Pro Tip**: Always use virtual environments to isolate dependencies

### 📥 **Import Syntax**

```javascript
// Node.js
const express = require("express");
import { Router } from "express";
```

```python
# Python
import fastapi
from fastapi import APIRouter
```

### 🔐 **Environment Variables**

- Both use `.env` files
- **Node.js**: `process.env.VAR_NAME`
- **Python**: `os.getenv("VAR_NAME")` with `python-dotenv`

### 🔍 **Type Checking & Linting**

| Node.js    | Python                 |
| ---------- | ---------------------- |
| TypeScript | mypy + type hints      |
| ESLint     | flake8 / ruff          |
| Prettier   | black                  |
| -          | isort (import sorting) |

### 🧪 **Testing**

- **Node.js**: Jest, Mocha, Chai
- **Python**: pytest, unittest, coverage.py

### 🌐 **Framework Comparison**

| Express.js        | FastAPI                         |
| ----------------- | ------------------------------- |
| Callback-based    | Async/await native              |
| Manual validation | Automatic validation (Pydantic) |
| Separate docs     | Auto-generated OpenAPI docs     |
| Middleware        | Middleware + Dependencies       |

---

## 2. 🏗️ Python Best Practice Project Structure

**🏆 Name**: Domain-Oriented Modular Monolith (src-layout pattern)

```
my_app/
├── 📁 src/
│   ├── 🚀 main.py              # FastAPI app entry
│   ├── ⚙️  config.py            # environment & settings
│   ├── 📝 logger.py            # JSON structured logging
│   ├── 👥 users/              # Domain: Users
│   │   ├── __init__.py
│   │   ├── 🌐 api.py           # FastAPI routes
│   │   ├── 📊 models.py        # Pydantic schemas
│   │   ├── 💼 service.py       # Business logic
│   │   ├── 💾 repository.py    # DB access (motor/pymongo)
│   │   └── 📧 events.py        # Domain events
│   ├── 🛒 orders/             # Domain: Orders
│   │   └── ...
│   ├── 🔧 shared/             # Cross-cutting utilities
│   │   ├── 🗄️  db.py           # SQLAlchemy sessions or motor client
│   │   ├── 💨 cache.py         # Redis client
│   │   ├── 📡 events.py        # Pub/Sub integration
│   │   ├── 🔒 auth.py          # JWT/OAuth utilities
│   │   └── 🛠️  utils.py
│   ├── 🔄 middlewares/        # Logging, CORS, rate limiting
│   ├── 📊 instrumentation/    # Prometheus metrics, tracing
│   └── 🏥 monitoring/         # Health checks
├── 🧪 tests/                  # Mirrors src/ for pytest
├── 📜 scripts/                # DB migrations, seeders
├── 🐋 docker/                 # Docker-related files
│   ├── Dockerfile.dev
│   └── Dockerfile.prod
├── 📚 docs/                   # API documentation
├── 🐋 .env.example
├── 📦 requirements.txt
├── 📦 requirements-dev.txt
├── 🐳 docker-compose.yml
├── 🌐 nginx/
│   └── nginx.conf          # Reverse proxy & SSL
├── 📖 README.md
├── 🚫 .gitignore
└── ⚙️  pyproject.toml         # Modern Python packaging
```

---

## 3. 📦 Package & Dependency Management

### 🎯 Core Dependencies

```bash
# Production dependencies
pip install fastapi uvicorn[standard] motor python-dotenv \
    prometheus-fastapi-instrumentator opentelemetry-api \
    opentelemetry-exporter-jaeger opentelemetry-instrumentation-fastapi \
    python-json-logger sentry-sdk redis httpx pydantic-settings \
    python-multipart python-jose[cryptography] passlib[bcrypt]

# Development dependencies
pip install pytest pytest-asyncio pytest-cov black flake8 mypy \
    pre-commit ipython rich

# Generate requirements
pip freeze > requirements.txt
```

### 🔧 Modern Dependency Management

```toml
# pyproject.toml (using Poetry)
[tool.poetry]
name = "my-app"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.104.0"
uvicorn = {extras = ["standard"], version = "^0.24.0"}

[tool.poetry.group.dev.dependencies]
pytest = "^7.4.0"
black = "^23.0.0"
```

---

## 4. ⚙️ Environment & Configuration

### 🔐 **.env.example**

```bash
# Application
APP_NAME=MyAwesomeAPI
APP_VERSION=1.0.0
ENV=production
DEBUG=false
LOG_LEVEL=INFO

# API Settings
API_V1_STR=/api/v1
SECRET_KEY=your-super-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/mydb
DB_POOL_SIZE=20
DB_POOL_MAX_OVERFLOW=40

# MongoDB
MONGO_URL=mongodb://mongo_user:mongo_pass@mongo:27017/mydb
MONGO_DB_NAME=mydb

# Redis
REDIS_URL=redis://redis:6379/0
REDIS_TTL=3600

# External Services
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project-id
JAEGER_AGENT_HOST=jaeger
JAEGER_AGENT_PORT=6831

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
```

### 🎯 **config.py** (Using Pydantic Settings)

```python
from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional

class Settings(BaseSettings):
    # Application
    app_name: str = "MyAwesomeAPI"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    # API Settings
    api_v1_str: str = "/api/v1"
    secret_key: str
    access_token_expire_minutes: int = 30

    # Database
    database_url: str
    db_pool_size: int = 20
    db_pool_max_overflow: int = 40

    # MongoDB
    mongo_url: str
    mongo_db_name: str = "mydb"

    # Redis
    redis_url: str
    redis_ttl: int = 3600

    # External Services
    sentry_dsn: Optional[str] = None
    jaeger_agent_host: str = "localhost"
    jaeger_agent_port: int = 6831

    # Rate Limiting
    rate_limit_per_minute: int = 60

    class Config:
        env_file = ".env"
        case_sensitive = False

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
```

---

## 5. 🚀 Running & Deployment

### 💻 Development

```bash
# With auto-reload
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# With custom env file
uvicorn src.main:app --reload --env-file .env.local
```

### 🏭 Production (Bare Metal)

```bash
# Using Gunicorn with Uvicorn workers
gunicorn src.main:app \
    -k uvicorn.workers.UvicornWorker \
    --workers 4 \
    --worker-connections 1000 \
    --max-requests 10000 \
    --max-requests-jitter 1000 \
    --timeout 60 \
    --graceful-timeout 30 \
    --access-logfile - \
    --error-logfile - \
    --bind 0.0.0.0:8000
```

### 🐳 Docker Production Setup

```dockerfile
# Dockerfile.prod
FROM python:3.11-slim as builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.11-slim

# Security: Run as non-root user
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appuser . .

USER appuser

# Add pip packages to PATH
ENV PATH=/home/appuser/.local/bin:$PATH

EXPOSE 8000

CMD ["gunicorn", "src.main:app", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]
```

### 🎯 Docker Compose

```yaml
version: "3.8"

services:
  api:
    build:
      context: .
      dockerfile: docker/Dockerfile.prod
    environment:
      - ENV=production
    ports:
      - "8000:8000"
    depends_on:
      - postgres
      - redis
      - mongo
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - api

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: mydb
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

  mongo:
    image: mongo:6
    environment:
      MONGO_INITDB_ROOT_USERNAME: mongo_user
      MONGO_INITDB_ROOT_PASSWORD: mongo_pass
    volumes:
      - mongo_data:/data/db

  redis:
    image: redis:7-alpine
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru

volumes:
  postgres_data:
  mongo_data:
```

---

## 6. 📊 Observability

### 📝 **Structured Logging**

```python
# logger.py
import logging
import sys
from pythonjsonlogger import jsonlogger
from contextvars import ContextVar
import uuid

# Context variable for request ID
request_id_var: ContextVar[str] = ContextVar('request_id', default='')

class RequestIDFilter(logging.Filter):
    def filter(self, record):
        record.request_id = request_id_var.get()
        return True

def setup_logging(log_level: str = "INFO"):
    handler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    handler.addFilter(RequestIDFilter())

    logger = logging.getLogger()
    logger.setLevel(log_level)
    logger.addHandler(handler)

    return logger
```

### 📈 **Metrics & Monitoring**

```python
# instrumentation/metrics.py
from prometheus_client import Counter, Histogram, Gauge
from prometheus_fastapi_instrumentator import Instrumentator
from fastapi import FastAPI

# Custom metrics
http_requests_total = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

request_duration_seconds = Histogram(
    'request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

active_connections = Gauge(
    'active_connections',
    'Number of active connections'
)

def setup_metrics(app: FastAPI):
    # Auto instrumentation
    Instrumentator().instrument(app).expose(app)

    # Custom middleware for metrics
    @app.middleware("http")
    async def track_metrics(request, call_next):
        method = request.method
        endpoint = request.url.path

        active_connections.inc()

        with request_duration_seconds.labels(
            method=method,
            endpoint=endpoint
        ).time():
            response = await call_next(request)

        http_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status=response.status_code
        ).inc()

        active_connections.dec()

        return response
```

### 🔍 **Distributed Tracing**

```python
# instrumentation/tracing.py
from opentelemetry import trace
from opentelemetry.exporter.jaeger import JaegerExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

def setup_tracing(app: FastAPI, service_name: str, jaeger_host: str, jaeger_port: int):
    trace.set_tracer_provider(TracerProvider())
    tracer = trace.get_tracer(__name__)

    jaeger_exporter = JaegerExporter(
        agent_host_name=jaeger_host,
        agent_port=jaeger_port,
    )

    span_processor = BatchSpanProcessor(jaeger_exporter)
    trace.get_tracer_provider().add_span_processor(span_processor)

    FastAPIInstrumentor.instrument_app(app, tracer_provider=trace.get_tracer_provider())

    return tracer
```

---

## 7. 🏥 Health Checks & Graceful Shutdown

### 💚 **Comprehensive Health Checks**

```python
# monitoring/health.py
from fastapi import APIRouter, status
from typing import Dict, Any
import asyncio
from datetime import datetime

router = APIRouter(tags=["monitoring"])

async def check_database() -> Dict[str, Any]:
    try:
        # Your DB check logic
        return {"status": "healthy", "response_time_ms": 15}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

async def check_redis() -> Dict[str, Any]:
    try:
        # Your Redis check logic
        return {"status": "healthy", "response_time_ms": 5}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

@router.get("/healthz")
async def health_check():
    checks = await asyncio.gather(
        check_database(),
        check_redis(),
        return_exceptions=True
    )

    db_health, redis_health = checks
    overall_health = all(
        check.get("status") == "healthy"
        for check in [db_health, redis_health]
        if isinstance(check, dict)
    )

    status_code = status.HTTP_200_OK if overall_health else status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "healthy" if overall_health else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": {
            "database": db_health,
            "redis": redis_health
        }
    }

@router.get("/readyz")
async def readiness_check():
    # Additional checks for readiness
    return {"status": "ready"}
```

### 🛑 **Graceful Shutdown**

```python
# main.py
import signal
import asyncio
from contextlib import asynccontextmanager

shutdown_event = asyncio.Event()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await startup_tasks()

    # Register signal handlers
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown()))

    yield

    # Shutdown
    await shutdown_tasks()

async def shutdown():
    logger.info("Received shutdown signal, starting graceful shutdown...")
    shutdown_event.set()

    # Wait for ongoing requests to complete (max 30 seconds)
    await asyncio.sleep(30)

    # Force shutdown
    logger.info("Forcing shutdown...")
    asyncio.get_event_loop().stop()

app = FastAPI(lifespan=lifespan)
```

---

## 8. 🔒 Security Best Practices

### 🛡️ **Security Headers & CORS**

```python
# middlewares/security.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

def setup_security_middleware(app: FastAPI):
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://app.example.com"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )

    # Trusted hosts
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["app.example.com", "*.example.com"]
    )

    # Security headers
    @app.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response
```

### 🔑 **JWT Authentication**

```python
# shared/auth.py
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm="HS256")
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username
```

### 🚦 **Rate Limiting**

```python
# middlewares/rate_limit.py
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict
import time

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, calls: int = 60, period: int = 60):
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.clients = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        now = time.time()

        # Clean old entries
        self.clients[client_ip] = [
            timestamp for timestamp in self.clients[client_ip]
            if timestamp > now - self.period
        ]

        if len(self.clients[client_ip]) >= self.calls:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded"
            )

        self.clients[client_ip].append(now)
        response = await call_next(request)
        return response
```

---

## 9. ⚡ Scalability & Reliability

### 🎯 **Performance Optimizations**

```python
# Async context manager for connection pooling
from motor.motor_asyncio import AsyncIOMotorClient
from redis import asyncio as aioredis
from contextlib import asynccontextmanager

class ConnectionManager:
    def __init__(self):
        self.mongo_client: Optional[AsyncIOMotorClient] = None
        self.redis_client: Optional[aioredis.Redis] = None

    async def connect(self):
        self.mongo_client = AsyncIOMotorClient(
            settings.mongo_url,
            maxPoolSize=50,
            minPoolSize=10
        )
        self.redis_client = await aioredis.create_redis_pool(
            settings.redis_url,
            maxsize=20
        )

    async def disconnect(self):
        if self.mongo_client:
            self.mongo_client.close()
        if self.redis_client:
            self.redis_client.close()
            await self.redis_client.wait_closed()

# Global connection manager
conn_manager = ConnectionManager()
```

### 🔄 **Circuit Breaker Pattern**

```python
# shared/circuit_breaker.py
from typing import Callable, Any
import asyncio
from datetime import datetime, timedelta

class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = Exception
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half_open

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        if self.state == "open":
            if datetime.now() - self.last_failure_time > timedelta(seconds=self.recovery_timeout):
                self.state = "half_open"
            else:
                raise Exception("Circuit breaker is open")

        try:
            result = await func(*args, **kwargs)
            if self.state == "half_open":
                self.state = "closed"
                self.failure_count = 0
            return result
        except self.expected_exception as e:
            self.failure_count += 1
            self.last_failure_time = datetime.now()

            if self.failure_count >= self.failure_threshold:
                self.state = "open"

            raise e
```

---

## 10. 🔧 CI/CD Pipeline Example (GitHub Actions)

```yaml
name: 🚀 CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  PYTHON_VERSION: "3.11"
  POETRY_VERSION: "1.6.1"

jobs:
  🧪-test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4

      - name: 🐍 Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ env.PYTHON_VERSION }}

      - name: 📦 Install Poetry
        uses: snok/install-poetry@v1
        with:
          version: ${{ env.POETRY_VERSION }}

      - name: 🔧 Install dependencies
        run: |
          poetry config virtualenvs.create true
          poetry config virtualenvs.in-project true
          poetry install --no-interaction --no-ansi

      - name: 🎨 Format check (Black)
        run: poetry run black --check src/ tests/

      - name: 🔍 Lint (Flake8)
        run: poetry run flake8 src/ tests/

      - name: 📋 Sort imports (isort)
        run: poetry run isort --check-only src/ tests/

      - name: 🔎 Type check (mypy)
        run: poetry run mypy src/

      - name: 🧪 Run tests
        run: |
          poetry run pytest \
            --cov=src \
            --cov-report=xml \
            --cov-report=term-missing \
            -v

      - name: 📊 Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml

  🔒-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: 🔐 Run Bandit security scan
        run: |
          pip install bandit
          bandit -r src/ -f json -o bandit-report.json

      - name: 🛡️ Run Safety check
        run: |
          pip install safety
          safety check --json

  🐳-build:
    needs: [🧪-test, 🔒-security]
    runs-on: ubuntu-latest
    if: github.event_name == 'push'

    steps:
      - uses: actions/checkout@v4

      - name: 🏷️ Generate version
        id: version
        run: |
          if [[ "${{ github.ref }}" == "refs/heads/main" ]]; then
            echo "tag=latest" >> $GITHUB_OUTPUT
          else
            echo "tag=${{ github.sha }}" >> $GITHUB_OUTPUT
          fi

      - name: 🐳 Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: 🔑 Login to DockerHub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}

      - name: 🏗️ Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./docker/Dockerfile.prod
          push: true
          tags: |
            ${{ secrets.DOCKER_USERNAME }}/myapp:${{ steps.version.outputs.tag }}
            ${{ secrets.DOCKER_USERNAME }}/myapp:${{ github.sha }}
          cache-from: type=registry,ref=${{ secrets.DOCKER_USERNAME }}/myapp:buildcache
          cache-to: type=registry,ref=${{ secrets.DOCKER_USERNAME }}/myapp:buildcache,mode=max

      - name: 🔍 Scan image with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ secrets.DOCKER_USERNAME }}/myapp:${{ github.sha }}
          format: "sarif"
          output: "trivy-results.sarif"

      - name: 📤 Upload Trivy results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: "trivy-results.sarif"

  🚀-deploy:
    needs: 🐳-build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'

    steps:
      - name: 🎯 Deploy to Kubernetes
        run: |
          # Your deployment logic here
          echo "Deploying to production..."
```

---

## 11. 🧪 Testing Strategy

### 🎯 **Test Structure**

```python
# tests/conftest.py
import pytest
from httpx import AsyncClient
from typing import AsyncGenerator
from src.main import app

@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.fixture
async def authenticated_client(client: AsyncClient) -> AsyncClient:
    # Login and set auth headers
    response = await client.post("/auth/login", json={
        "username": "testuser",
        "password": "testpass"
    })
    token = response.json()["access_token"]
    client.headers["Authorization"] = f"Bearer {token}"
    return client
```

### 🧪 **Test Examples**

```python
# tests/test_users.py
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_create_user(client: AsyncClient):
    response = await client.post("/api/v1/users", json={
        "username": "johndoe",
        "email": "john@example.com",
        "password": "securepass123"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "johndoe"
    assert "password" not in data

@pytest.mark.asyncio
async def test_get_user_authenticated(authenticated_client: AsyncClient):
    response = await authenticated_client.get("/api/v1/users/me")
    assert response.status_code == 200
```

### 📊 **Test Coverage Configuration**

```ini
# setup.cfg
[coverage:run]
source = src
omit =
    */tests/*
    */migrations/*
    */__init__.py

[coverage:report]
precision = 2
show_missing = True
skip_covered = False

[coverage:html]
directory = htmlcov
```

---

## 12. ✅ Final FAANG-Level Checklist

### 🏗️ **Architecture & Code Quality**

- [ ] 📁 Domain-oriented project structure (src-layout)
- [ ] 🐍 Python 3.11+ with type hints everywhere
- [ ] 📦 Poetry or pip-tools for reproducible builds
- [ ] 🎨 Code formatting with Black + isort
- [ ] 🔍 Linting with Flake8/Ruff + mypy for type checking
- [ ] 📝 Comprehensive docstrings and type annotations
- [ ] 🧪 90%+ test coverage with pytest

### 🔧 **Configuration & Environment**

- [ ] ⚙️ Pydantic Settings for type-safe configuration
- [ ] 🔐 Environment-specific configs (.env.local, .env.prod)
- [ ] 🔑 Secrets management (Vault, AWS Secrets Manager)
- [ ] 📋 Configuration validation on startup

### 📊 **Observability & Monitoring**

- [ ] 📝 JSON structured logging with correlation IDs
- [ ] 📈 Prometheus metrics with custom business metrics
- [ ] 🔍 OpenTelemetry distributed tracing
- [ ] 🚨 Sentry or similar for error tracking
- [ ] 📊 APM integration (DataDog, New Relic)
- [ ] 🏥 Comprehensive health checks (/healthz, /readyz)

### 🔒 **Security**

- [ ] 🛡️ HTTPS only with proper SSL/TLS configuration
- [ ] 🌐 CORS properly configured for your domains
- [ ] 🔑 JWT/OAuth2 authentication with refresh tokens
- [ ] 🚦 Rate limiting per user/IP
- [ ] 🛡️ Security headers (CSP, HSTS, etc.)
- [ ] 🔍 Regular dependency vulnerability scanning
- [ ] 🐳 Container security scanning with Trivy
- [ ] 🔐 SQL injection protection via ORMs
- [ ] 🛡️ Input validation with Pydantic

### ⚡ **Performance & Scalability**

- [ ] 🚀 Async/await throughout the codebase
- [ ] 🔄 Connection pooling for databases
- [ ] 💨 Redis caching strategy implemented
- [ ] 📊 Database query optimization and indexing
- [ ] 🎯 API response pagination
- [ ] 🔄 Circuit breakers for external services
- [ ] ⚡ CDN for static assets
- [ ] 🗜️ Response compression (gzip/brotli)

### 🐳 **Deployment & Infrastructure**

- [ ] 🐋 Multi-stage Docker builds (<100MB images)
- [ ] 🔧 Docker Compose for local development
- [ ] ☸️ Kubernetes manifests with proper resource limits
- [ ] 🔄 Rolling updates with zero downtime
- [ ] 🎯 Horizontal pod autoscaling (HPA)
- [ ] 🌐 Service mesh integration (Istio/Linkerd)
- [ ] 📦 Helm charts for different environments
- [ ] 🔧 Infrastructure as Code (Terraform/Pulumi)

### 🔄 **CI/CD & DevOps**

- [ ] 🧪 Automated testing on every commit
- [ ] 🎨 Code quality gates (coverage, linting)
- [ ] 🔒 Security scanning in pipeline
- [ ] 🐳 Automated Docker builds and pushes
- [ ] 🚀 GitOps deployment strategy
- [ ] 📊 Performance testing in CI
- [ ] 🔄 Automated rollback capabilities
- [ ] 📈 Deployment metrics and notifications

### 📚 **Documentation & Standards**

- [ ] 📖 OpenAPI/Swagger auto-generated docs
- [ ] 📝 README with setup and contribution guide
- [ ] 🏗️ Architecture decision records (ADRs)
- [ ] 📋 API versioning strategy (/api/v1/)
- [ ] 🔄 Changelog maintenance
- [ ] 📊 Performance benchmarks documented

### 🎯 **Advanced Features**

- [ ] 🔄 WebSocket support for real-time features
- [ ] 📡 Event-driven architecture (Kafka/RabbitMQ)
- [ ] 🗄️ Database migrations with Alembic
- [ ] 🔍 Full-text search (Elasticsearch)
- [ ] 📊 GraphQL endpoint (optional)
- [ ] 🌍 Internationalization (i18n) support
- [ ] 📱 Multi-tenancy support
- [ ] 🔐 API key management for B2B

### 🚨 **Disaster Recovery**

- [ ] 💾 Automated database backups
- [ ] 🔄 Point-in-time recovery capability
- [ ] 📊 Disaster recovery runbooks
- [ ] 🎯 RTO/RPO defined and tested
- [ ] 🌍 Multi-region deployment strategy

---

## 🎯 Quick Start Commands

```bash
# 🚀 Create new project
mkdir my-awesome-api && cd my-awesome-api
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 📦 Install dependencies
pip install fastapi uvicorn[standard] python-dotenv

# 🏗️ Create project structure
mkdir -p src/{users,orders,shared,middlewares,instrumentation,monitoring}
touch src/{main.py,config.py,logger.py}

# 🚀 Run development server
uvicorn src.main:app --reload

# 🧪 Run tests
pytest -v --cov=src

# 🐳 Build and run with Docker
docker-compose up -d --build

# 📊 Check metrics
curl http://localhost:8000/metrics

# 🏥 Check health
curl http://localhost:8000/healthz
```

---

> 💡 **Pro Tips:**
>
> - Start with a simple MVP and gradually add complexity
> - Focus on business logic first, optimize later
> - Use async/await by default for all I/O operations
> - Invest in good logging and monitoring early
> - Keep your dependencies up to date
> - Document your API decisions in ADRs

🎉 **Happy coding with FastAPI!** 🐍✨

---

## 13. 🐍 Python Crash Course for Node.js Developers

> 🚀 **Quick Python essentials to get you productive fast!**

### 📚 **Python Syntax Basics**

#### 🔤 **Variables & Data Types**

```python
# Variables (no const/let/var needed)
name = "John"          # string
age = 30               # integer
height = 5.9           # float
is_active = True       # boolean (True/False, not true/false)
items = [1, 2, 3]      # list (like array)
person = {"name": "John", "age": 30}  # dict (like object)

# Type hints (optional but recommended)
name: str = "John"
age: int = 30
items: list[int] = [1, 2, 3]
```

#### 🎯 **Functions**

```python
# Basic function
def greet(name):
    return f"Hello, {name}!"

# With type hints
def greet(name: str) -> str:
    return f"Hello, {name}!"

# Default parameters
def greet(name: str = "World") -> str:
    return f"Hello, {name}!"

# Multiple return values
def get_name_age() -> tuple[str, int]:
    return "John", 30

name, age = get_name_age()  # Destructuring

# Async functions
async def fetch_data(url: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        return response.json()
```

#### 🏗️ **Classes**

```python
# Basic class
class User:
    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email

    def greet(self) -> str:
        return f"Hello, I'm {self.name}"

    @property
    def display_name(self) -> str:
        return self.name.title()

# Inheritance
class AdminUser(User):
    def __init__(self, name: str, email: str, permissions: list[str]):
        super().__init__(name, email)
        self.permissions = permissions

    def can_access(self, resource: str) -> bool:
        return resource in self.permissions

# Data classes (like TypeScript interfaces)
from dataclasses import dataclass

@dataclass
class Product:
    id: int
    name: str
    price: float
    in_stock: bool = True
```

#### 📦 **Imports & Modules**

```python
# Import entire module
import os
import json
from datetime import datetime

# Import specific functions/classes
from fastapi import FastAPI, HTTPException
from typing import Optional, List, Dict

# Import with alias
import pandas as pd
import numpy as np

# Relative imports (within your package)
from .models import User
from ..shared.utils import hash_password
```

### 🔄 **Control Flow**

#### 🔀 **Conditionals**

```python
# if/elif/else (no braces needed, indentation matters!)
if age >= 18:
    print("Adult")
elif age >= 13:
    print("Teenager")
else:
    print("Child")

# Ternary operator
status = "adult" if age >= 18 else "minor"

# Check for None (like null)
if user is not None:
    print(user.name)

# Check if value exists
if user and user.name:
    print(user.name)
```

#### 🔁 **Loops**

```python
# For loops
for item in items:
    print(item)

# With index
for i, item in enumerate(items):
    print(f"{i}: {item}")

# Range loops
for i in range(5):  # 0 to 4
    print(i)

for i in range(1, 10, 2):  # 1, 3, 5, 7, 9
    print(i)

# While loops
count = 0
while count < 5:
    print(count)
    count += 1

# List comprehensions (like array.map)
numbers = [1, 2, 3, 4, 5]
squares = [x**2 for x in numbers]  # [1, 4, 9, 16, 25]
evens = [x for x in numbers if x % 2 == 0]  # [2, 4]
```

### 📊 **Data Structures**

#### 📋 **Lists (Arrays)**

```python
# Creating lists
fruits = ["apple", "banana", "orange"]
numbers = [1, 2, 3, 4, 5]

# List methods
fruits.append("grape")           # Add to end
fruits.insert(0, "strawberry")  # Insert at position
fruits.remove("banana")         # Remove by value
popped = fruits.pop()           # Remove and return last
fruits.extend(["kiwi", "mango"]) # Add multiple

# List slicing
first_three = fruits[:3]        # First 3 items
last_two = fruits[-2:]          # Last 2 items
reversed_list = fruits[::-1]    # Reverse

# Useful list functions
length = len(fruits)
sorted_fruits = sorted(fruits)
joined = ", ".join(fruits)      # "apple, banana, orange"
```

#### 📖 **Dictionaries (Objects)**

```python
# Creating dictionaries
user = {
    "name": "John",
    "age": 30,
    "email": "john@example.com"
}

# Accessing values
name = user["name"]              # Throws error if key doesn't exist
name = user.get("name")          # Returns None if key doesn't exist
name = user.get("name", "Unknown")  # Default value

# Dictionary methods
user["age"] = 31                 # Update
user.update({"city": "NYC"})     # Update multiple
del user["email"]                # Delete key
keys = list(user.keys())         # Get all keys
values = list(user.values())     # Get all values

# Dictionary comprehension
squares = {x: x**2 for x in range(5)}  # {0: 0, 1: 1, 2: 4, 3: 9, 4: 16}
```

### 🔧 **Python-Specific Features**

#### 🎭 **Context Managers (with statements)**

```python
# File handling (auto-closes file)
with open("file.txt", "r") as file:
    content = file.read()

# Database connections
with get_db() as db:
    users = db.query(User).all()

# Custom context manager
from contextlib import contextmanager

@contextmanager
def timer():
    start = time.time()
    yield
    print(f"Took {time.time() - start:.2f} seconds")

with timer():
    # Your code here
    time.sleep(1)
```

#### 🎁 **Decorators**

```python
# Function decorators
def log_calls(func):
    def wrapper(*args, **kwargs):
        print(f"Calling {func.__name__}")
        return func(*args, **kwargs)
    return wrapper

@log_calls
def greet(name):
    return f"Hello, {name}"

# Class decorators
@dataclass
class User:
    name: str
    email: str

# Property decorators
class Circle:
    def __init__(self, radius):
        self._radius = radius

    @property
    def area(self):
        return 3.14 * self._radius ** 2

    @property
    def radius(self):
        return self._radius

    @radius.setter
    def radius(self, value):
        if value < 0:
            raise ValueError("Radius must be positive")
        self._radius = value
```

#### 🔀 **Exception Handling**

```python
# Try/except (like try/catch)
try:
    result = 10 / 0
except ZeroDivisionError as e:
    print(f"Error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
else:
    print("No errors occurred")
finally:
    print("This always runs")

# Raising exceptions
def divide(a, b):
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b

# Custom exceptions
class UserNotFoundError(Exception):
    pass

def get_user(user_id):
    if not user_exists(user_id):
        raise UserNotFoundError(f"User {user_id} not found")
```

### 🚀 **Async/Await (Like Node.js)**

```python
import asyncio
import httpx

# Async function
async def fetch_user(user_id: int) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"/users/{user_id}")
        return response.json()

# Multiple async calls
async def fetch_multiple_users(user_ids: list[int]) -> list[dict]:
    tasks = [fetch_user(user_id) for user_id in user_ids]
    return await asyncio.gather(*tasks)

# Running async code
async def main():
    users = await fetch_multiple_users([1, 2, 3])
    print(users)

# Run the async function
if __name__ == "__main__":
    asyncio.run(main())
```

### 📦 **Package Management & Virtual Environments**

#### 🐍 **Virtual Environments**

```bash
# Create virtual environment
python -m venv myproject_env

# Activate (Linux/Mac)
source myproject_env/bin/activate

# Activate (Windows)
myproject_env\Scripts\activate

# Deactivate
deactivate

# Install packages
pip install fastapi uvicorn

# Save dependencies
pip freeze > requirements.txt

# Install from requirements
pip install -r requirements.txt
```

#### 📝 **Poetry (Modern Package Manager)**

```bash
# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Create new project
poetry new myproject
cd myproject

# Add dependencies
poetry add fastapi uvicorn
poetry add --group dev pytest black mypy

# Install dependencies
poetry install

# Run in virtual environment
poetry run python main.py
poetry run pytest

# Activate shell
poetry shell
```

### 🛠️ **Common Python Libraries for Web Development**

```python
# Web frameworks
from fastapi import FastAPI, Depends, HTTPException
from flask import Flask, request, jsonify

# Data validation
from pydantic import BaseModel, validator
from typing import Optional, List

# Database ORMs
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from motor.motor_asyncio import AsyncIOMotorClient  # MongoDB

# HTTP clients
import httpx  # Async HTTP client
import requests  # Sync HTTP client

# Environment variables
from dotenv import load_dotenv
import os

# Date/time
from datetime import datetime, timedelta
import pytz

# JSON handling
import json

# Logging
import logging
from python_json_logger import jsonlogger

# Testing
import pytest
from unittest.mock import Mock, patch

# Data manipulation
import pandas as pd
import numpy as np
```

### 🎯 **Python Best Practices for Node.js Developers**

#### ✅ **Do's**

```python
# Use type hints everywhere
def process_user(user: User) -> UserResponse:
    return UserResponse(name=user.name)

# Use dataclasses for simple data containers
@dataclass
class ApiResponse:
    status: str
    data: dict
    message: Optional[str] = None

# Use f-strings for string formatting
name = "John"
message = f"Hello, {name}!"  # Not "Hello, " + name + "!"

# Use list/dict comprehensions
user_names = [user.name for user in users]
user_dict = {user.id: user.name for user in users}

# Use context managers for resources
with open("config.json") as f:
    config = json.load(f)

# Use async/await for I/O operations
async def get_user_data(user_id: int) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"/users/{user_id}")
        return response.json()
```

#### ❌ **Don'ts**

```python
# Don't use mutable default arguments
def add_item(item, items=[]):  # ❌ Bad
    items.append(item)
    return items

def add_item(item, items=None):  # ✅ Good
    if items is None:
        items = []
    items.append(item)
    return items

# Don't use bare except clauses
try:
    risky_operation()
except:  # ❌ Bad - catches everything
    pass

try:
    risky_operation()
except SpecificError as e:  # ✅ Good
    handle_error(e)

# Don't compare with True/False/None using ==
if is_valid == True:  # ❌ Bad
    pass

if is_valid:  # ✅ Good
    pass

if user is None:  # ✅ Good for None checks
    pass
```

### 🔥 **Quick Reference: Node.js vs Python**

| Concept                  | Node.js                         | Python                        |
| ------------------------ | ------------------------------- | ----------------------------- |
| **Variables**            | `const name = "John"`           | `name = "John"`               |
| **Functions**            | `function greet() {}`           | `def greet():`                |
| **Arrow Functions**      | `const add = (a, b) => a + b`   | `add = lambda a, b: a + b`    |
| **Classes**              | `class User {}`                 | `class User:`                 |
| **Imports**              | `import { User } from './user'` | `from .user import User`      |
| **Async/Await**          | `async function fetch() {}`     | `async def fetch():`          |
| **Arrays**               | `[1, 2, 3].map(x => x * 2)`     | `[x * 2 for x in [1, 2, 3]]`  |
| **Objects**              | `{ name: "John", age: 30 }`     | `{"name": "John", "age": 30}` |
| **String Interpolation** | `` `Hello, ${name}!` ``         | `f"Hello, {name}!"`           |
| **Null Check**           | `if (user != null)`             | `if user is not None:`        |
| **Error Handling**       | `try/catch`                     | `try/except`                  |
| **Comments**             | `// comment` or `/* block */`   | `# comment` or `"""block"""`  |

### 🚀 **FastAPI Quick Start Example**

```python
# main.py
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
import uvicorn

app = FastAPI(title="My API", version="1.0.0")

# Pydantic models (like TypeScript interfaces)
class UserCreate(BaseModel):
    name: str
    email: str
    age: Optional[int] = None

class User(BaseModel):
    id: int
    name: str
    email: str
    age: Optional[int] = None

# In-memory database (use real DB in production)
users_db: List[User] = []
next_id = 1

# Routes
@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.post("/users", response_model=User, status_code=201)
async def create_user(user: UserCreate):
    global next_id
    new_user = User(id=next_id, **user.dict())
    users_db.append(new_user)
    next_id += 1
    return new_user

@app.get("/users", response_model=List[User])
async def get_users():
    return users_db

@app.get("/users/{user_id}", response_model=User)
async def get_user(user_id: int):
    for user in users_db:
        if user.id == user_id:
            return user
    raise HTTPException(status_code=404, detail="User not found")

# Run the server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
```

### 🧪 **Testing Example**

```python
# test_main.py
import pytest
from httpx import AsyncClient
from main import app

@pytest.mark.asyncio
async def test_create_user():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/users", json={
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30
        })

    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "John Doe"
    assert data["email"] == "john@example.com"
    assert data["age"] == 30
    assert "id" in data

@pytest.mark.asyncio
async def test_get_users():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        # Create a user first
        await ac.post("/users", json={
            "name": "Jane Doe",
            "email": "jane@example.com"
        })

        # Get all users
        response = await ac.get("/users")

    assert response.status_code == 200
    users = response.json()
    assert len(users) >= 1
```

### 🎯 **Practice Exercises**

1. **Convert this Node.js function to Python:**

```javascript
// Node.js
function calculateTotal(items) {
  return items
    .filter((item) => item.price > 0)
    .reduce((total, item) => total + item.price, 0);
}
```

<details>
<summary>👆 Click for Python solution</summary>

```python
# Python
def calculate_total(items: list[dict]) -> float:
    return sum(item["price"] for item in items if item["price"] > 0)

# Or more explicit:
def calculate_total(items: list[dict]) -> float:
    filtered_items = [item for item in items if item["price"] > 0]
    return sum(item["price"] for item in filtered_items)
```

</details>

2. **Create a FastAPI endpoint that:**
   - Accepts a list of user IDs
   - Returns user data for each ID
   - Handles missing users gracefully

<details>
<summary>👆 Click for solution</summary>

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

class UserRequest(BaseModel):
    user_ids: List[int]

class User(BaseModel):
    id: int
    name: str
    email: str

@app.post("/users/batch", response_model=List[User])
async def get_users_batch(request: UserRequest):
    found_users = []
    for user_id in request.user_ids:
        user = await get_user_from_db(user_id)
        if user:
            found_users.append(user)
    return found_users
```

</details>

### 🎓 **Next Steps**

1. **Practice Python basics** - Solve coding problems on LeetCode/HackerRank
2. **Build a simple FastAPI project** - Start with a TODO API
3. **Learn async patterns** - Practice with async/await
4. **Explore the ecosystem** - SQLAlchemy, Pydantic, pytest
5. **Read production code** - Study open-source FastAPI projects

### 📚 **Additional Resources**

- 📖 [Official Python Tutorial](https://docs.python.org/3/tutorial/)
- 🚀 [FastAPI Documentation](https://fastapi.tiangolo.com/)
- 🐍 [Real Python](https://realpython.com/) - Excellent tutorials
- 📝 [Python Type Hints](https://docs.python.org/3/library/typing.html)
- 🧪 [Pytest Documentation](https://docs.pytest.org/)

---

> 🎯 **Remember**: Python emphasizes readability and simplicity. If you're coming from Node.js, focus on learning the Pythonic way of doing things rather than directly translating JavaScript patterns!
