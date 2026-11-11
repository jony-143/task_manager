import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from models import User, Task
from dependencies import get_db
from main import app
from config import settings
from tests.token_factory import BAD_HEADERS
from tests.helpers import make_auth_headers

if not settings.DATABASE_URL.endswith("_test") or settings.DATABASE_URL != settings.TEST_DATABASE_URL:
    raise pytest.UsageError(
        "Test environment not loaded: DATABASE_URL must point to the test database")


# ---------------- MARKERS ----------------


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "task_count(count): number of tasks created by the new_tasks fixture",
    )


# ---------------- DATABASE SETUP ----------------


engine = create_engine(
    settings.TEST_DATABASE_URL,
    echo=False,
    pool_size=5,  # Number of persistent connections
    max_overflow=10,  # Number of extra temporary connections beyond pool_size
    pool_timeout=30,  # Maximum wait time for a connection from the pool
    pool_recycle=1800,  # Recycle connections after this many seconds
    pool_pre_ping=True,        # handles dead connections
    pool_reset_on_return="rollback",  # rollback open transactions on connection return
)

TestSessionLocal = sessionmaker(
    engine, autoflush=False, expire_on_commit=False)


def get_db_test():
    db = TestSessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ---------------- FIXTURES ----------------


@pytest.fixture()
def db_session():
    db = TestSessionLocal()
    yield db
    db.close()


@pytest.fixture(scope="session", autouse=True)
def conf_db_test():
    app.dependency_overrides[get_db] = get_db_test
    yield
    app.dependency_overrides = {}


@pytest.fixture(scope="module")
def client(conf_db_test):
    return TestClient(app)


# ----------- DATA FIXTURES ----------------


@pytest.fixture(scope="function")
def admin_data():
    return {
        "username": "admin_user",
        "email": "admin_user@example.com",
        "password": "password",
    }


@pytest.fixture(scope="function")
def user_data():
    return {
        "username": "test_user",
        "email": "test_user@example.com",
        "password": "password",
    }


@pytest.fixture(scope="function")
def task_data():
    return {
        "title": "Test Task",
        "description": "This is a test task",
    }


# -------- CLEANUP FIXTURES ----------------


@pytest.fixture(scope="function")
def track_created_users(db_session):
    user_ids = set()
    yield user_ids

    failures = []
    deleted_any = False

    for user_id in user_ids:
        user = db_session.get(User, user_id)
        if not user:
            failures.append(user_id)
        else:
            db_session.delete(user)
            deleted_any = True
    if deleted_any:
        db_session.commit()
    if failures:
        pytest.fail("Failed to cleanup users: " + str(failures))


@pytest.fixture(scope="function")
def track_created_tasks(db_session, track_created_users):
    task_ids = set()
    yield task_ids

    failures = []
    deleted_any = False

    for task_id in task_ids:
        task = db_session.get(Task, task_id)
        if not task:
            failures.append(task_id)
        else:
            db_session.delete(task)
            deleted_any = True
    if deleted_any:
        db_session.commit()
    if failures:
        pytest.fail("Failed to cleanup tasks: " + str(failures))


# -------- CREATION FIXTURES ----------------


@pytest.fixture(scope="function", params=BAD_HEADERS.keys())
def make_bad_token(request):
    return BAD_HEADERS[request.param]


@pytest.fixture(scope="function")
def make_user(client, track_created_users):
    def _make(data):
        r = client.post("/users/", json=data)
        if r.status_code != 201:
            pytest.fail(f"Registration failed: {r.status_code} {r.text}")
        user = r.json()
        track_created_users.add(user["id"])
        return user
    return _make


@pytest.fixture(scope="function")
def login_as(client):
    def _login(data):
        r = client.post("/auth/token", data={
            "username": data["email"], "password": data["password"]})
        if r.status_code != 200:
            pytest.fail(f"Login failed: {r.status_code} {r.text}")
        return r.json()
    return _login


@pytest.fixture(scope="function")
def make_tasks(client, track_created_tasks):
    def _make(data, headers, count=1):
        created = []
        for i in range(count):
            payload = {**data, "title": f"{data['title']} {i + 1}"}
            r = client.post("/tasks/", headers=headers, json=payload)
            if r.status_code != 201:
                pytest.fail(f"Task creation failed: {r.status_code} {r.text}")
            created.append(r.json())
            track_created_tasks.add(r.json()["id"])
        return created
    return _make


@pytest.fixture(scope="function")
def set_inactive_user(db_session):
    def _set(user_id):
        user = db_session.get(User, user_id)
        if not user:
            pytest.fail(f"User with id {user_id} not found")
        user.is_active = False
        db_session.commit()
        return user
    return _set


@pytest.fixture(scope="function")
def set_admin_user(db_session):
    def _set(user_id):
        user = db_session.get(User, user_id)
        if not user:
            pytest.fail(f"User with id {user_id} not found")
        user.is_admin = True
        db_session.commit()
        return user
    return _set


# ----------- SETUP FIXTURES ----------------

@pytest.fixture(scope="function")
def new_user(make_user, user_data):
    return make_user(user_data)


@pytest.fixture(scope="function")
def login(new_user, login_as, user_data):
    return login_as(user_data)


# @pytest.mark.task_count(2) for test
@pytest.fixture(scope="function")
def new_tasks(request, login, task_data, make_tasks):
    marker = request.node.get_closest_marker("task_count")
    if marker is None:
        pytest.fail("Add @pytest.mark.task_count(count) to the test")
    return make_tasks(task_data, make_auth_headers(login), marker.args[0])


@pytest.fixture(scope="function")
def new_admin_user(db_session, make_user, admin_data, set_admin_user):
    admin = make_user(admin_data)
    set_admin_user(admin["id"])
    return admin


@pytest.fixture(scope="function")
def admin_login(new_admin_user, login_as, admin_data):
    return login_as(admin_data)
