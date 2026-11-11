# Endpoints:
# 1) GET /tasks/
# 2) GET /tasks/{task_id}
# 3) POST /tasks/
# 4) PATCH /tasks/{task_id}
# 5) DELETE /tasks/{task_id}

# For every endpoint, need to test authentication:
# I) All kinds of malformed token and headers
# II) Valid token but insufficient permissions (inactive user)
# III) Valid token and sufficient permissions (normal operation)

# About authorization:
# Every endpoint requires an active user (or 403). Admin is never required
# Always check ownership of resources:
# 1) All tasks and nothing more
# 2) Can't access other user task (404)
# 3) Check user_id in database
# 4) Can't modify other user task (404)
# 5) Can't delete other user task (404)

# About database and other side effects:
# 1) --
# 2) --
# 3) Check DB after calling endpoint, all fields you can
# 4) Check DB after calling endpoint, all fields, modified or not
# 5) Check DB after calling endpoint, resource should be deleted and not found

# For every endpoint, check status code and body, everything that is
# defined in the API. Specially in positive cases, but also in errors.
# Check headers if defined in the API.
# Check side effects in the database if applicable, always in the cases
# I specified above.

from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from models import Task
from tests.helpers import make_auth_headers


TASK_RESPONSE_FIELDS = {
    "id",
    "user_id",
    "title",
    "description",
    "completed",
    "created_at",
}

TASK_ENDPOINTS = [
    pytest.param("GET", "/tasks/", id="list"),
    pytest.param("GET", "/tasks/{task_id}", id="get"),
    pytest.param("POST", "/tasks/", id="create"),
    pytest.param("PATCH", "/tasks/{task_id}", id="update"),
    pytest.param("DELETE", "/tasks/{task_id}", id="delete"),
]


def assert_task_response(data, task):
    assert set(data) == TASK_RESPONSE_FIELDS
    assert type(data["id"]) is int
    assert type(data["user_id"]) is int
    assert type(data["title"]) is str
    assert type(data["description"]) is str
    assert type(data["completed"]) is bool
    assert type(data["created_at"]) is str

    assert data["id"] == task.id
    assert data["user_id"] == task.user_id
    assert data["title"] == task.title
    assert data["description"] == task.description
    assert data["completed"] == task.completed

    response_created_at = datetime.fromisoformat(data["created_at"])
    database_created_at = task.created_at
    if database_created_at.tzinfo is None:
        database_created_at = database_created_at.replace(tzinfo=timezone.utc)
    assert response_created_at == database_created_at


def task_request(client, method, endpoint, headers, task_id, body):
    path = endpoint.format(task_id=task_id)
    return client.request(method, path, headers=headers, json=body)


def assert_owned_tasks_unchanged(db_session, user_id, expected_tasks):
    tasks = db_session.scalars(
        select(Task).where(Task.user_id == user_id).order_by(Task.id)
    ).all()
    expected_by_id = {task["id"]: task for task in expected_tasks}
    assert [task.id for task in tasks] == sorted(expected_by_id)
    for task in tasks:
        assert_task_response(expected_by_id[task.id], task)


@pytest.mark.task_count(1)
@pytest.mark.parametrize(("method", "endpoint"), TASK_ENDPOINTS)
def test_task_endpoints_bad_tokens(
    db_session,
    client,
    new_user,
    new_tasks,
    make_bad_token,
    user_data,
    task_data,
    method,
    endpoint,
):
    task_id = new_tasks[0]["id"]
    headers = make_bad_token(user_data["username"])
    if method == "PATCH":
        body = {
            "title": "Unauthorized update",
            "description": "This must not be saved",
            "completed": True,
        }
    elif method == "POST":
        body = task_data
    else:
        body = None

    response = task_request(
        client, method, endpoint, headers, task_id, body)

    assert response.status_code == 401
    assert response.json() == {
        "detail": (
            "Could not validate credentials"
            if headers.get("Authorization", "").split(" ", 1)[0] == "Bearer"
            else "Not authenticated"
        )
    }
    assert response.headers.get("www-authenticate") == "Bearer"
    assert_owned_tasks_unchanged(
        db_session, new_user["id"], new_tasks)


@pytest.mark.task_count(1)
@pytest.mark.parametrize(("method", "endpoint"), TASK_ENDPOINTS)
def test_task_endpoints_inactive_user(
    db_session,
    client,
    new_user,
    new_tasks,
    login,
    user_data,
    task_data,
    set_inactive_user,
    method,
    endpoint,
):
    set_inactive_user(new_user["id"])
    if method == "PATCH":
        body = {
            "title": "Unauthorized update",
            "description": "This must not be saved",
            "completed": True,
        }
    elif method == "POST":
        body = task_data
    else:
        body = None

    response = task_request(
        client,
        method,
        endpoint,
        make_auth_headers(login),
        new_tasks[0]["id"],
        body,
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Inactive user"}
    assert_owned_tasks_unchanged(
        db_session, new_user["id"], new_tasks)


@pytest.mark.task_count(2)
def test_list_tasks(
    db_session,
    client,
    new_user,
    new_tasks,
    login,
    user_data,
    task_data,
    make_user,
    login_as,
    make_tasks,
):
    other_user_data = {
        **user_data,
        "username": "other_test_user",
        "email": "other_test_user@example.com",
    }
    other_user = make_user(other_user_data)
    other_login = login_as(other_user_data)
    other_tasks = make_tasks(
        task_data, make_auth_headers(other_login), count=1)

    response = client.get("/tasks/", headers=make_auth_headers(login))

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == len(new_tasks)
    assert data == new_tasks
    # Content checked against the inputs, not only against the fixture
    for i, response_task in enumerate(data):
        assert response_task["user_id"] == new_user["id"]
        assert response_task["title"] == f"{task_data['title']} {i + 1}"
        assert response_task["description"] == task_data["description"]
        assert response_task["completed"] is False
    for response_task, task_data_item in zip(data, new_tasks):
        task = db_session.get(Task, task_data_item["id"])
        assert task is not None
        assert task.user_id == new_user["id"]
        assert_task_response(response_task, task)
    assert other_tasks[0]["id"] not in [task["id"] for task in data]


@pytest.mark.task_count(1)
def test_get_task(
    db_session,
    client,
    new_user,
    login,
    new_tasks,
    user_data,
    task_data,
    make_user,
    login_as,
    make_tasks,
):
    own_task = new_tasks[0]
    response = client.get(
        f"/tasks/{own_task['id']}", headers=make_auth_headers(login))

    assert response.status_code == 200
    # Public contract testing
    assert response.json() == own_task
    # Content checked against the inputs, not only against the fixture
    data = response.json()
    assert data["user_id"] == new_user["id"]
    assert data["title"] == f"{task_data['title']} 1"
    assert data["description"] == task_data["description"]
    assert data["completed"] is False
    task = db_session.get(Task, own_task["id"])
    assert task is not None
    assert task.user_id == new_user["id"]
    assert_task_response(response.json(), task)

    other_user_data = {
        **user_data,
        "username": "other_test_user",
        "email": "other_test_user@example.com",
    }
    other_user = make_user(other_user_data)
    other_login = login_as(other_user_data)
    other_task = make_tasks(
        task_data, make_auth_headers(other_login), count=1)[0]

    foreign_response = client.get(
        f"/tasks/{other_task['id']}", headers=make_auth_headers(login))
    assert foreign_response.status_code == 404
    assert foreign_response.json() == {"detail": "Task not found"}
    persisted_other_task = db_session.get(Task, other_task["id"])
    assert persisted_other_task is not None
    assert persisted_other_task.user_id == other_user["id"]
    assert_task_response(other_task, persisted_other_task)


def test_create_task(
    db_session,
    client,
    new_user,
    login,
    task_data,
    track_created_tasks,
):
    response = client.post(
        "/tasks/", headers=make_auth_headers(login), json=task_data)

    assert response.status_code == 201
    data = response.json()
    track_created_tasks.add(data["id"])

    # Public contract testing
    assert set(data) == TASK_RESPONSE_FIELDS
    assert isinstance(data["id"], int)
    assert data["user_id"] == new_user["id"]
    assert data["title"] == task_data["title"]
    assert data["description"] == task_data["description"]
    assert data["completed"] is False
    created_at = datetime.fromisoformat(data["created_at"])
    assert abs(datetime.now(timezone.utc) - created_at).total_seconds() < 60

    # Persistence testing (side effect)
    task = db_session.get(Task, data["id"])
    assert task is not None
    assert task.user_id == new_user["id"]
    assert task.title == task_data["title"]
    assert task.description == task_data["description"]
    assert task.completed is False
    assert task.created_at is not None
    assert_task_response(data, task)


@pytest.mark.task_count(1)
def test_update_task(
    db_session,
    client,
    new_user,
    new_tasks,
    login,
    user_data,
    task_data,
    make_user,
    login_as,
    make_tasks,
):
    own_task = new_tasks[0]
    other_user_data = {
        **user_data,
        "username": "other_test_user",
        "email": "other_test_user@example.com",
    }
    other_user = make_user(other_user_data)
    other_login = login_as(other_user_data)
    other_task = make_tasks(
        task_data, make_auth_headers(other_login), count=1)[0]

    foreign_response = client.patch(
        f"/tasks/{other_task['id']}",
        headers=make_auth_headers(login),
        json={"title": "Unauthorized update"},
    )
    assert foreign_response.status_code == 404
    assert foreign_response.json() == {"detail": "Task not found"}
    persisted_other_task = db_session.get(Task, other_task["id"])
    assert persisted_other_task is not None
    assert persisted_other_task.user_id == other_user["id"]
    assert_task_response(other_task, persisted_other_task)

    response = client.patch(
        f"/tasks/{own_task['id']}",
        headers=make_auth_headers(login),
        json={"title": "Updated task",
              "description": "Updated description", "completed": True},
    )

    assert response.status_code == 200
    # Public contract testing: only the sent fields change
    assert response.json() == {
        **own_task,
        "title": "Updated task",
        "description": "Updated description",
        "completed": True,
    }
    task = db_session.get(Task, own_task["id"])
    assert task is not None
    assert task.user_id == new_user["id"]
    assert task.title == "Updated task"
    assert task.description == "Updated description"
    assert task.completed is True
    assert task.created_at is not None
    assert response.json()["created_at"] == own_task["created_at"]
    assert_task_response(response.json(), task)


@pytest.mark.task_count(1)
def test_delete_task(
    db_session,
    client,
    new_user,
    new_tasks,
    login,
    user_data,
    task_data,
    make_user,
    login_as,
    make_tasks,
    track_created_tasks,
):
    own_task = new_tasks[0]
    other_user_data = {
        **user_data,
        "username": "other_test_user",
        "email": "other_test_user@example.com",
    }
    other_user = make_user(other_user_data)
    other_login = login_as(other_user_data)
    other_task = make_tasks(
        task_data, make_auth_headers(other_login), count=1)[0]

    foreign_response = client.delete(
        f"/tasks/{other_task['id']}", headers=make_auth_headers(login))
    assert foreign_response.status_code == 404
    assert foreign_response.json() == {"detail": "Task not found"}
    persisted_other_task = db_session.get(Task, other_task["id"])
    assert persisted_other_task is not None
    assert persisted_other_task.user_id == other_user["id"]
    assert_task_response(other_task, persisted_other_task)

    response = client.delete(
        f"/tasks/{own_task['id']}", headers=make_auth_headers(login))

    assert response.status_code == 204
    assert response.content == b""
    assert db_session.get(Task, own_task["id"]) is None
    track_created_tasks.discard(own_task["id"])


@pytest.mark.task_count(1)
@pytest.mark.parametrize(
    ("method", "body"),
    [
        pytest.param("GET", None, id="get"),
        pytest.param(
            "PATCH",
            {
                "title": "Missing task update",
                "description": "This task does not exist",
                "completed": True,
            },
            id="patch",
        ),
        pytest.param("DELETE", None, id="delete"),
    ],
)
def test_task_endpoints_nonexistent_task_id(
    db_session,
    client,
    new_user,
    new_tasks,
    login,
    method,
    body,
):
    missing_task_id = -1
    assert db_session.get(Task, missing_task_id) is None
    tasks_before = [
        (
            task.id,
            task.user_id,
            task.title,
            task.description,
            task.completed,
            task.created_at,
        )
        for task in db_session.scalars(select(Task).order_by(Task.id)).all()
    ]

    response = client.request(
        method,
        f"/tasks/{missing_task_id}",
        headers=make_auth_headers(login),
        json=body,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Task not found"}
    assert db_session.get(Task, missing_task_id) is None
    tasks_after = [
        (
            task.id,
            task.user_id,
            task.title,
            task.description,
            task.completed,
            task.created_at,
        )
        for task in db_session.scalars(select(Task).order_by(Task.id)).all()
    ]
    assert tasks_after == tasks_before
