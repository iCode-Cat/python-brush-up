# Python FastAPI Production Guide for Node.js Developers — FAANG-Level

## 1. Original Node.js → Python Mapping Notes

1. **Packages & Modules**

   - Node: `npm`, `package.json`
   - Python: `pip`, `requirements.txt` or `pyproject.toml`
   - Create virtual environment (`venv`) instead of `node_modules`.

2. **Import Syntax**

   - Node: `require('module')` or `import {} from 'module'`
   - Python: `import module` or `from module import Class`

3. **Environment Variables**

   - `.env` convention in both ecosystems.
   - Python loads with `python-dotenv`.

4. **Type Checking & Linting**

   - Node: TypeScript, ESLint.
   - Python: `mypy`, `flake8`, `black`.

5. **Testing**

   - Node: Jest, Mocha.
   - Python: `pytest`.

6. **Framework**
   - Node: Express.js.
   - Python: FastAPI (modern, async, auto-docs) or Flask.

---

## 2. Python Best Practice Project Structure

**Name**: Domain-Oriented Modular Monolith (src-layout pattern)

```
my_app/
├── src/
│   ├── main.py             # FastAPI app entry
│   ├── config.py           # environment & settings
│   ├── logger.py           # JSON structured logging
│   ├── users/              # Domain: Users
│   │   ├── __init__.py
│   │   ├── api.py          # FastAPI routes
│   │   ├── models.py       # Pydantic schemas
│   │   ├── service.py      # Business logic
│   │   └── repository.py   # DB access (motor/pymongo)
│   ├── orders/             # Domain: Orders
│   │   └── ...
│   ├── shared/             # Cross-cutting utilities
│   │   ├── db.py           # SQLAlchemy sessions or motor client
│   │   ├── cache.py        # Redis client
│   │   ├── events.py       # Pub/Sub integration
│   │   └── utils.py
│   ├── middlewares/        # Logging, CORS, rate limiting
│   ├── instrumentation/    # Prometheus metrics, tracing
│   └── monitoring/         # Health checks
├── tests/                  # Mirrors src/ for pytest
├── scripts/                # DB migrations, seeders
├── .env
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── nginx/
│   └── nginx.conf          # Reverse proxy & SSL
├── README.md
└── .gitignore
```

---

## 3. Package & Dependency Management

```bash
pip install fastapi uvicorn motor python-dotenv prometheus-fastapi-instrumentator     opentelemetry-api opentelemetry-exporter-jaeger opentelemetry-instrumentation-fastapi     python-json-logger sentry-sdk
pip freeze > requirements.txt
```

- Manage versions with `pipenv` or `poetry` for lockfiles.

---

## 4. Environment & Configuration

**.env**

```
DATABASE_URL=postgresql://user:pass@host/db
MONGO_URL=mongodb://mongo_user:mongo_pass@mongo:27017/mydb
REDIS_URL=redis://redis:6379/0
SENTRY_DSN=https://...
ENV=production
```

**config.py**

```python
from dotenv import load_dotenv
import os

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
MONGO_URL = os.getenv("MONGO_URL")
REDIS_URL = os.getenv("REDIS_URL")
SENTRY_DSN = os.getenv("SENTRY_DSN")
ENV = os.getenv("ENV", "development")
```

---

## 5. Running & Deployment

### Development

```bash
uvicorn src.main:app --reload
```

### Production (bare metal)

```bash
gunicorn -k uvicorn.workers.UvicornWorker src.main:app     --workers 4 --bind 0.0.0.0:8000
```

### Docker Compose

```bash
docker-compose up -d --build
```

---

## 6. Observability

- **Logging**: JSON logs via `python-json-logger`, include correlation ID.
- **Metrics**: Expose `/metrics` for Prometheus using `prometheus-fastapi-instrumentator`.
- **Tracing**: Use OpenTelemetry middleware to export to Jaeger.

---

## 7. Health Checks & Graceful Shutdown

- **Health endpoint** (`/healthz`) checks DB, Redis status.
- Use FastAPI `on_startup` / `on_shutdown` to manage connections.

---

## 8. Security Best Practices

- **HTTPS only**: SSL termination in Nginx or LB.
- **CORS**: FastAPI’s `CORSMiddleware` for allowed origins.
- **Auth**: JWT/OAuth2 via FastAPI dependencies.
- **Secrets**: Use Vault or cloud secrets manager, not static `.env` in prod.
- **Image scanning**: CI pipeline runs `trivy`.

---

## 9. Scalability & Reliability

- **Gunicorn + Uvicorn** workers for CPU-bound concurrency.
- **Kubernetes readiness/liveness**: probes to `/healthz`.
- **Rolling updates**: zero-downtime via Kubernetes Deployments.
- **Rate limiting**: via middleware or API Gateway.

---

## 10. CI/CD Pipeline Example (GitHub Actions)

```yaml
name: CI

on: [push]

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: "3.11"
      - name: Install dependencies
        run: |
          python -m venv venv
          source venv/bin/activate
          pip install -r requirements.txt
      - name: Lint & format
        run: |
          black src/
          flake8 src/
      - name: Type check
        run: mypy src/
      - name: Test
        run: pytest
      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .
      - name: Scan Docker image
        run: trivy image myapp:${{ github.sha }}
      - name: Push to registry
        run: |
          echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
          docker push myapp:${{ github.sha }}
      - name: Deploy to Kubernetes
        run: kubectl set image deployment/myapp myapp=myapp:${{ github.sha }}
```

---

## 11. Testing Strategy

- **Unit tests**: mock repositories.
- **Integration tests**: use `pytest` with Docker containers for DB.
- **E2E tests**: `pytest` + `httpx` against running service.

---

## 12. Final FAANG-Level Checklist

- [ ] Domain-oriented project structure (src-layout).
- [ ] Virtualenv or Poetry for dependency isolation.
- [ ] Environment config via `.env` / secrets manager.
- [ ] JSON structured logging with correlation IDs.
- [ ] Prometheus metrics and `/metrics` endpoint.
- [ ] OpenTelemetry tracing to Jaeger/Zipkin.
- [ ] Health checks (`/healthz`) and graceful shutdown.
- [ ] HTTPS & CORS configured securely.
- [ ] JWT/OAuth2 authentication layer.
- [ ] Docker security scanning (Trivy).
- [ ] Gunicorn + Uvicorn multi-worker setup.
- [ ] Nginx reverse proxy for SSL, HTTP/2.
- [ ] Kubernetes readiness/liveness probes.
- [ ] CI/CD pipeline: lint, type-check, test, build, scan, deploy.
- [ ] Rate limiting and API versioning (`/api/v1/...`).
- [ ] Sentry (or similar) for error tracking.
- [ ] Zero-downtime deployments.
- [ ] Ephemeral staging environments for PR testing.
