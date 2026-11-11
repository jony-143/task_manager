# Task Management API

A portfolio and learning REST API demonstrating modern backend practices for security, testing, modular architecture, and database management.

## AI-Assisted Development

Developed with AI pair-programming tools (GitHub Copilot) as a learning accelerator: understanding tools and concepts, getting examples, and exploring architecture and design-pattern suggestions. Some test modules were AI-generated from templates I had already written; I reviewed and validated the work.

## Tech Stack

| Category | Technologies |
| ---------- | --------------- |
| **Backend Framework** | FastAPI, Uvicorn, Starlette |
| **Database** | PostgreSQL, SQLAlchemy 2.0 ORM |
| **Database Migrations** | Alembic |
| **Authentication & Security** | JWT (PyJWT), Argon2 password hashing (pwdlib) |
| **Data Validation** | Pydantic v2 |
| **Testing** | Pytest, pytest-cov, TestClient (httpx), pytest-env |
| **Environment & Config** | Python-dotenv, pydantic-settings |

## Key Features

### Authentication & Authorization

- JWT access tokens with expiration and required-claim validation
- Role-based access control (RBAC): reusable dependencies restrict admin endpoints to active admin users
- Object-level authorization (resource ownership): users can read, update, and delete only their own tasks; requests for another user's task return the same `404 Task not found` response as a nonexistent task, avoiding disclosure of whether that task exists
- Argon2 password hashing
- Password confirmation before a user deletes their own account
- A dummy password hash is checked when a login email is unknown to reduce timing differences between unknown-account and wrong-password cases

### Database & Data Management

- Object-relational mapping (ORM): SQLAlchemy maps the `User` and `Task` Python models and their relationships to PostgreSQL tables
- A CRUD/data-access layer centralizes database operations; it serves a DAO-like role without implementing a separate formal DAO abstraction
- Alembic migrations for versioned schema changes
- Unique constraints for usernames and emails
- Foreign-key and ORM cascades for deleting a user's tasks
- Timezone-aware task creation timestamps

### API Design & Validation

- REST endpoints with explicit HTTP methods, response models, and status codes
- DTO-style API models: separate Pydantic request and response schemas (for example, `UserCreate` and `UserOut`) validate and shape data at the API boundary, without exposing password hashes in user responses
- Dependency injection for database sessions and access control
- Limit/offset pagination

### Testing

- API tests cover authentication, authorization, user management, task operations, and admin operations
- Tests use a dedicated PostgreSQL database and cleanup fixtures
- The latest local test run passed **226 tests** and reported **98% total coverage**, including test modules

## Project Structure

```text
task_manager/
├── main.py                 # FastAPI application entry point
├── config.py               # Environment configuration
├── database.py             # SQLAlchemy engine and session setup
├── models.py               # User and Task ORM models
├── schemas.py              # Pydantic request/response schemas
├── crud.py                 # Database operations
├── security.py             # JWT and password utilities
├── dependencies.py         # Database and authorization dependencies
├── routers/
│   ├── auth.py              # Authentication endpoints
│   ├── users.py             # User registration and self-service deletion
│   ├── tasks.py             # User-owned task operations
│   └── admin.py             # Admin-only operations
├── alembic/                 # Migration configuration and revisions
└── tests/                   # API tests, fixtures, and test configuration
```

## Getting Started

### Prerequisites

- Python 3.x
- PostgreSQL 12+

### Installation

1. Create and activate a virtual environment:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Create a local `.env` based on `.env.example`. Generate a secret key with:

   ```powershell
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

   Set `DATABASE_URL`, `TEST_DATABASE_URL`, `SECRET_KEY`, and `ALGORITHM` in `.env`. Use separate databases for the application and tests. Keep `.env` local; do not commit credentials or secrets.

4. Create a PostgreSQL role and databases, choosing your own local password:

   ```sql
   CREATE USER task_manager WITH PASSWORD 'replace-with-a-local-password';
   CREATE DATABASE taskdb OWNER task_manager;
   CREATE DATABASE taskdb_test OWNER task_manager;
   ```

   Configure the URLs in `.env` (URL-encode reserved characters in the password):

   ```dotenv
   DATABASE_URL=postgresql+psycopg2://task_manager:YOUR_PASSWORD@localhost:5432/taskdb
   TEST_DATABASE_URL=postgresql+psycopg2://task_manager:YOUR_PASSWORD@localhost:5432/taskdb_test
   ```

5. Apply the application database migrations:

   ```powershell
   alembic upgrade head
   ```

6. Start the API:

   ```powershell
   fastapi dev main.py
   # For FastAPI's production server mode:
   fastapi run main.py
   ```

The API is available at `http://localhost:8000`.

## API Documentation

- Swagger UI: <http://localhost:8000/docs>
- ReDoc: <http://localhost:8000/redoc>
- OpenAPI schema: <http://localhost:8000/openapi.json>

## Security Notes

- JWT decoding checks the configured signing algorithm, expiration, and required `sub` and `exp` claims.
- Passwords are stored as Argon2 hashes, not plaintext.
- Admin routes require an active admin; task routes require an active user and enforce task ownership.
- SQLAlchemy expression-based queries bind values rather than constructing SQL from user input.
- Pydantic schemas and FastAPI validate request bodies and pagination bounds.

This project does **not** currently configure CORS, rate limiting, or HTTPS-enforcement middleware. Since these are important security features, I will be working on them for future versions of the project.

## Tests

The test configuration loads `tests/.env.test`; configure it to point `DATABASE_URL` and `TEST_DATABASE_URL` at the dedicated test database. The test setup refuses to run unless those URLs match and end in `_test`. Ensure the test database has the current Alembic schema before running the suite.

Run all tests with coverage:

```powershell
python -m pytest tests\ --cov=. --cov-report=term-missing
```

Run one module or test:

```powershell
python -m pytest tests\test_auth.py -v
python -m pytest tests\test_auth.py::test_auth_valid -v
```

Show `print()` output with `-s`.

## Database Migrations

Create a migration after changing models:

```powershell
alembic revision --autogenerate -m "description of changes"
```

Review autogenerated migrations before applying them. Then use:

```powershell
alembic upgrade head
```

To inspect the PostgreSQL schema, use:

```powershell
psql -U USERNAME -d taskdb -c "\d user_account"
psql -U USERNAME -d taskdb -c "\d task"
```

## API Endpoints

### Authentication

- `POST /auth/token` — Log in and receive an access token

### Users

- `POST /users/` — Register a user
- `DELETE /users/me` — Delete the authenticated user after password confirmation

### Tasks

- `POST /tasks/` — Create a task
- `GET /tasks/` — List the authenticated user's tasks with pagination
- `GET /tasks/{task_id}` — Get an owned task
- `PATCH /tasks/{task_id}` — Update an owned task
- `DELETE /tasks/{task_id}` — Delete an owned task

### Admin

- `GET /admin/users` — List users with pagination
- `GET /admin/tasks` — List tasks with pagination
- `PATCH /admin/users/{user_id}` — Update a user's active/admin flags
- `DELETE /admin/users/{user_id}` — Delete a user (except the acting admin)
- `DELETE /admin/tasks/{task_id}` — Delete a task

## Configuration

`DATABASE_URL`, `TEST_DATABASE_URL`, `SECRET_KEY`, and `ALGORITHM` are required settings. Add `TEST_DATABASE_URL` to `.env` even if it is not present in `.env.example`. Other settings include token lifetime and pagination defaults/maximums.

## Future Enhancements

- [ ] Async database operations
- [ ] Redis caching
- [ ] Cursor-based pagination
- [ ] Background task processing
- [ ] Logging and error tracking
- [ ] Rate limiting, CORS and HTTPS-enforcement
- [ ] API versioning
- [ ] Additional user-profile endpoints
- [ ] More boundary-focused input validation tests
