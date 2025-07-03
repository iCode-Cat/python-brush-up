# 📝 Python Backend with FastAPI, Docker, Gunicorn, Nginx, MongoDB — Plus All Developer Notes

---

## 📒 Original Notes (as a Node.js Developer)

1. A directory is treated as a package (that you can import) only if it contains an `__init__.py` file.

   - Without it, Python before 3.3 would not recognize it as a package.
   - Even though modern Python allows implicit packages, best practice is to include `__init__.py` for clarity and tooling.

2. The concept of `.env` is not tied to any language.

   - It’s a general convention for storing environment variables as plain text (`KEY=value`).
   - Python uses the same `.env` file convention, typically loaded with `python-dotenv`.

3. `pip` is Python’s equivalent of `npm`.

   - Installs packages from PyPI (Python Package Index).
   - Typical commands:
     pip install requests
     pip freeze > requirements.txt
     pip install -r requirements.txt

4. Python uses virtual environments (`venv`) instead of global `node_modules`.

   - Keeps dependencies isolated.
   - Typical workflow:
     python -m venv venv
     source venv/bin/activate
     pip install -r requirements.txt

5. Folder structure in Python backends is often organized by domain / feature, not by technical type.

   - Example:
     users/
     api.py
     models.py
     service.py
     orders/
     shared/
     main.py
   - This is called a domain-oriented or feature-based project structure, inspired by DDD (Domain-Driven Design).

6. Python uses `import` instead of `require`.

   - Example:
     from fastapi import FastAPI
     from users import service

7. Type checking in Python is optional, but you can use type hints + `mypy`.

   - Example:
     def add(a: int, b: int) -> int:
     return a + b

8. Common tooling:

   - `flake8` for linting (like `eslint`).
   - `black` for formatting (like `prettier`).
   - `pytest` for testing (like `jest`).
   - `mypy` for type checks (like `tsc` for TypeScript).

9. FastAPI is a modern Python web framework similar to Express, but with built-in data validation and automatic docs.
   - Run with `uvicorn`:
     uvicorn main:app --reload

---

## 📚 Enhanced Professional Cheat Sheet (System Design, Docker, Nginx, MongoDB)

[Includes everything from above plus advanced system design, production deployment, MongoDB, Nginx, Docker.]

---

## 📦 Package & Dependency Management

pip install fastapi uvicorn motor python-dotenv
pip freeze > requirements.txt
pip install -r requirements.txt

---

## 🐍 Virtual Environments

python -m venv venv
source venv/bin/activate # Mac/Linux
venv\Scripts\activate # Windows

---

## 🌿 Environment Configuration (`.env`)

DATABASE_URL=postgresql://user:pass@localhost/db
SECRET_KEY=mysecret
MONGO_URL=mongodb://mongo_user:mongo_pass@localhost:27017/mydb
ENV=development

---

## 📂 Project Structure — Domain-Driven Modular Monolith

my_app/
│
├── src/
│ ├── main.py # FastAPI app + router inclusion
│ ├── config.py # loads .env vars into global settings
│ ├── logger.py # structured logging setup
│
│ ├── users/
│ │ ├── **init**.py
│ │ ├── api.py # FastAPI APIRouter with endpoints
│ │ ├── models.py # Pydantic schemas & domain types
│ │ ├── service.py # business logic, uses repo
│ │ └── repository.py # Mongo/SQL DB queries
│
│ ├── orders/
│ │ ├── **init**.py
│ │ ├── api.py
│ │ ├── models.py
│ │ ├── service.py
│ │ └── repository.py
│
│ ├── shared/
│ │ ├── **init**.py
│ │ ├── db.py # SQLAlchemy sessions / Postgres
│ │ ├── mongo.py # motor client for MongoDB
│ │ ├── cache.py # Redis client (if needed)
│ │ ├── events.py # pub/sub events or message broker
│ │ └── utils.py # general helpers
│
├── tests/
│ ├── **init**.py
│ ├── test_users.py
│ ├── test_orders.py
│ └── conftest.py # pytest fixtures
│
├── scripts/
│ ├── seed_db.py
│ └── migrate_db.py
│
├── .env
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── nginx/
│ └── nginx.conf
├── README.md
└── .gitignore

---

## ✅ FastAPI Usage

from fastapi import FastAPI
from users.api import router as users_router

app = FastAPI()
app.include_router(users_router)

Run locally:

uvicorn src.main:app --reload

---

## 🚀 Production with Gunicorn & Nginx

gunicorn -k uvicorn.workers.UvicornWorker src.main:app --workers 4 --bind 0.0.0.0:8000

Nginx config (/etc/nginx/sites-available/myapp):

server {
listen 80;
server_name myapp.com;
location / {
proxy_pass http://127.0.0.1:8000;
proxy_redirect off;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
}
}

sudo ln -s /etc/nginx/sites-available/myapp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

---

## 🐳 Docker + Docker Compose

Dockerfile:

FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
COPY .env config.py logger.py ./
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "src.main:app", "--workers=4", "--bind=0.0.0.0:8000"]

docker-compose.yml with Mongo:

version: "3.8"
services:
web:
build: .
ports: - "8000:8000"
env_file: - .env
depends_on: - mongo

mongo:
image: mongo:6
restart: always
environment:
MONGO_INITDB_ROOT_USERNAME: mongo_user
MONGO_INITDB_ROOT_PASSWORD: mongo_pass
volumes: - mongodb_data:/data/db

volumes:
mongodb_data:

Run everything:

docker-compose up -d --build

---

## 🔌 MongoDB Usage with Motor

from motor.motor_asyncio import AsyncIOMotorClient
from config import MONGO_URL

client = AsyncIOMotorClient(MONGO_URL)
db = client.get_default_database()

Example repository:

class UserRepository:
async def find_by_email(self, email: str):
return await db.users.find_one({"email": email})

    async def create_user(self, user_data: dict):
        result = await db.users.insert_one(user_data)
        return str(result.inserted_id)

---

## ✅ Quick Reference Commands

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
black src/
flake8 src/
mypy src/
pytest
uvicorn src.main:app --reload
gunicorn -k uvicorn.workers.UvicornWorker src.main:app --workers 4 --bind 0.0.0.0:8000
docker-compose up -d --build

---

## 📝 Professional Best Practices

- Organize by domain / feature.
- Use `__init__.py` for packages.
- Load config with `.env`.
- Keep HTTP, services, repositories separate (clean architecture).
- Dockerize, use Gunicorn + Nginx for production.
- Structured logs, tracing, metrics for observability.
