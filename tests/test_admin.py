# Endpoints:
# 1) DELETE /admin/users/{user_id}
# 2) DELETE /admin/tasks/{task_id}
# 3) GET /admin/users
# 4) GET /admin/tasks
# 5) PATCH /admin/users/{user_id}

from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from config import settings
from models import Task, User
from security import verify_password
from tests.helpers import make_auth_headers


USER_RESPONSE_FIELDS = {"id", "username", "email", "is_active", "is_admin"}
TASK_RESPONSE_FIELDS = {
    "id",
    "user_id",
    "title",
    "description",
    "completed",
    "created_at",
}

ADMIN_ENDPOINTS = [
    pytest.param("DELETE", "/admin/users/{user_id}", id="delete_user"),
    pytest.param("DELETE", "/admin/tasks/{task_id}", id="delete_task"),
    pytest.param("GET", "/admin/users", id="list_users"),
    pytest.param("GET", "/admin/tasks", id="list_tasks"),
    pytest.param("PATCH", "/admin/users/{user_id}", id="update_user"),
]

# Differs from the stored values of a regular user (is_active=True, is_admin=False)
PATCH_BODY = {"is_active": False, "is_admin": True}


# ---------------- HELPERS ----------------


def user_state(user):
    return (
        user.id,
        user.username,
        user.email,
        user.password_hash,
        user.is_active,
        user.is_admin,
    )


def task_state(task):
    return (
        task.id,
        task.user_id,
        task.title,
        task.description,
        task.completed,
        task.created_at,
    )


def snapshot_all(db_session):
    users = db_session.scalars(select(User).order_by(User.id)).all()
    tasks = db_session.scalars(select(Task).order_by(Task.id)).all()
    return [user_state(u) for u in users], [task_state(t) for t in tasks]


def assert_user_response(data, user):
    assert set(data) == USER_RESPONSE_FIELDS
    assert type(data["id"]) is int
    assert type(data["username"]) is str
    assert type(data["email"]) is str
    assert type(data["is_active"]) is bool
    assert type(data["is_admin"]) is bool

    assert data["id"] == user.id
    assert data["username"] == user.username
    assert data["email"] == user.email
    assert data["is_active"] == user.is_active
    assert data["is_admin"] == user.is_admin


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


def admin_request(client, method, endpoint, headers, user_id, task_id):
    path = endpoint.format(user_id=user_id, task_id=task_id)
    body = PATCH_BODY if method == "PATCH" else None
    return client.request(method, path, headers=headers, json=body)


def other_user_data(user_data):
    return {
        **user_data,
        "username": "other_test_user",
        "email": "other_test_user@example.com",
    }


# ---------------- AUTHENTICATION ----------------


@pytest.mark.task_count(1)
@pytest.mark.parametrize(("method", "endpoint"), ADMIN_ENDPOINTS)
def test_admin_endpoints_bad_tokens(
    db_session,
    client,
    new_admin_user,
    new_user,
    new_tasks,
    make_bad_token,
    admin_data,
    method,
    endpoint,
):
    headers = make_bad_token(admin_data["username"])
    before = snapshot_all(db_session)

    response = admin_request(
        client, method, endpoint, headers, new_user["id"], new_tasks[0]["id"])

    assert response.status_code == 401
    assert response.json() == {
        "detail": (
            "Could not validate credentials"
            if headers.get("Authorization", "").split(" ", 1)[0] == "Bearer"
            else "Not authenticated"
        )
    }
    assert response.headers.get("www-authenticate") == "Bearer"
    assert snapshot_all(db_session) == before


@pytest.mark.task_count(1)
@pytest.mark.parametrize(("method", "endpoint"), ADMIN_ENDPOINTS)
def test_admin_endpoints_inactive_admin(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    new_tasks,
    set_inactive_user,
    method,
    endpoint,
):
    set_inactive_user(new_admin_user["id"])
    before = snapshot_all(db_session)

    response = admin_request(
        client,
        method,
        endpoint,
        make_auth_headers(admin_login),
        new_user["id"],
        new_tasks[0]["id"],
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Inactive user"}
    assert snapshot_all(db_session) == before


# ---------------- AUTHORIZATION ----------------


@pytest.mark.parametrize(("method", "endpoint"), ADMIN_ENDPOINTS)
def test_admin_endpoints_non_admin_user(
    db_session,
    client,
    login,
    user_data,
    task_data,
    make_user,
    login_as,
    make_tasks,
    method,
    endpoint,
):
    # Every request targets another user's resources, so it would
    # succeed if the caller were an admin: only the role can reject it
    aux_user_data = other_user_data(user_data)
    aux_user = make_user(aux_user_data)
    aux_login = login_as(aux_user_data)
    aux_task = make_tasks(task_data, make_auth_headers(aux_login), count=1)[0]
    before = snapshot_all(db_session)

    response = admin_request(
        client,
        method,
        endpoint,
        make_auth_headers(login),
        aux_user["id"],
        aux_task["id"],
    )

    assert response.status_code == 403
    assert response.json() == {
        "detail": "The user doesn't have enough privileges"}
    assert snapshot_all(db_session) == before


# ---------------- GET /admin/users ----------------


def test_get_all_users(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    user_data,
    make_user,
):
    aux_user = make_user(other_user_data(user_data))

    response = client.get(
        "/admin/users",
        headers=make_auth_headers(admin_login),
        params={"limit": settings.USER_MAX_LIMIT},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

    # Public contract testing: users created by this test, with admin fields
    assert {**new_admin_user, "is_active": True, "is_admin": True} in data
    assert {**new_user, "is_active": True, "is_admin": False} in data
    assert {**aux_user, "is_active": True, "is_admin": False} in data

    # Persistence testing: the response is exactly what the database holds
    db_users = db_session.scalars(select(User).order_by(User.id)).all()
    assert len(data) == len(db_users)
    for response_user, db_user in zip(data, db_users):
        assert_user_response(response_user, db_user)

    # Pagination
    paged = client.get(
        "/admin/users",
        headers=make_auth_headers(admin_login),
        params={"limit": 2, "offset": 1},
    )
    assert paged.status_code == 200
    assert paged.json() == data[1:3]


# ---------------- GET /admin/tasks ----------------


@pytest.mark.task_count(2)
def test_get_all_tasks(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    new_tasks,
    user_data,
    task_data,
    make_user,
    login_as,
    make_tasks,
):
    aux_user_data = other_user_data(user_data)
    aux_user = make_user(aux_user_data)
    aux_login = login_as(aux_user_data)
    aux_tasks = make_tasks(
        task_data, make_auth_headers(aux_login), count=1)

    response = client.get(
        "/admin/tasks",
        headers=make_auth_headers(admin_login),
        params={"limit": settings.TASK_MAX_LIMIT},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

    # Public contract testing: tasks of every user, not only the admin's
    for i, task in enumerate(new_tasks):
        assert task in data
        assert task["user_id"] == new_user["id"]
        assert task["title"] == f"{task_data['title']} {i + 1}"
        assert task["description"] == task_data["description"]
        assert task["completed"] is False
    assert aux_tasks[0] in data
    assert aux_tasks[0]["user_id"] == aux_user["id"]

    # Persistence testing: the response is exactly what the database holds
    db_tasks = db_session.scalars(select(Task).order_by(Task.id)).all()
    assert len(data) == len(db_tasks)
    for response_task, db_task in zip(data, db_tasks):
        assert_task_response(response_task, db_task)

    # Pagination
    paged = client.get(
        "/admin/tasks",
        headers=make_auth_headers(admin_login),
        params={"limit": 2, "offset": 1},
    )
    assert paged.status_code == 200
    assert paged.json() == data[1:3]


@pytest.mark.parametrize("endpoint", ["/admin/users", "/admin/tasks"])
@pytest.mark.parametrize("params", [
    pytest.param({"limit": 0}, id="limit_zero"),
    pytest.param({"limit": 10**9}, id="limit_too_big"),
    pytest.param({"offset": -1}, id="offset_negative"),
    pytest.param({"offset": 10**9}, id="offset_too_big"),
])
def test_admin_list_invalid_pagination(
    db_session,
    client,
    new_admin_user,
    admin_login,
    endpoint,
    params,
):
    before = snapshot_all(db_session)

    response = client.get(
        endpoint, headers=make_auth_headers(admin_login), params=params)

    assert response.status_code == 422
    assert isinstance(response.json()["detail"], list)
    assert snapshot_all(db_session) == before


# ---------------- DELETE /admin/users/{user_id} ----------------


@pytest.mark.task_count(2)
def test_delete_user(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    new_tasks,
    user_data,
    task_data,
    make_user,
    login_as,
    make_tasks,
    track_created_users,
    track_created_tasks,
):
    aux_user_data = other_user_data(user_data)
    aux_user = make_user(aux_user_data)
    aux_login = login_as(aux_user_data)
    aux_task = make_tasks(
        task_data, make_auth_headers(aux_login), count=1)[0]
    admin_before = user_state(db_session.get(User, new_admin_user["id"]))
    aux_user_before = user_state(db_session.get(User, aux_user["id"]))
    aux_task_before = task_state(db_session.get(Task, aux_task["id"]))

    response = client.delete(
        f"/admin/users/{new_user['id']}",
        headers=make_auth_headers(admin_login),
    )

    assert response.status_code == 204
    assert response.content == b""

    # Persistence testing (side effect)
    assert db_session.get(User, new_user["id"]) is None
    track_created_users.discard(new_user["id"])

    # Cascade: the tasks of the deleted user are deleted too
    for task in new_tasks:
        assert db_session.get(Task, task["id"]) is None
        track_created_tasks.discard(task["id"])

    # Other users and their tasks are not affected
    assert user_state(
        db_session.get(User, new_admin_user["id"])) == admin_before
    assert user_state(db_session.get(User, aux_user["id"])) == aux_user_before
    assert task_state(db_session.get(Task, aux_task["id"])) == aux_task_before


@pytest.mark.task_count(1)
def test_delete_user_self(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    new_tasks,
    task_data,
    make_tasks,
):
    admin_task = make_tasks(
        task_data, make_auth_headers(admin_login), count=1)[0]
    before = snapshot_all(db_session)

    response = client.delete(
        f"/admin/users/{new_admin_user['id']}",
        headers=make_auth_headers(admin_login),
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Admin user cannot delete themselves"}
    assert snapshot_all(db_session) == before
    assert db_session.get(User, new_admin_user["id"]) is not None
    assert db_session.get(Task, admin_task["id"]) is not None


@pytest.mark.task_count(1)
def test_delete_user_nonexistent(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    new_tasks,
):
    missing_user_id = -1
    assert db_session.get(User, missing_user_id) is None
    before = snapshot_all(db_session)

    response = client.delete(
        f"/admin/users/{missing_user_id}",
        headers=make_auth_headers(admin_login),
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}
    assert snapshot_all(db_session) == before


# ---------------- DELETE /admin/tasks/{task_id} ----------------


@pytest.mark.task_count(2)
def test_delete_task(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    new_tasks,
    track_created_tasks,
):
    # The admin deletes a task owned by another user
    deleted_task, kept_task = new_tasks
    kept_task_before = task_state(db_session.get(Task, kept_task["id"]))
    user_before = user_state(db_session.get(User, new_user["id"]))

    response = client.delete(
        f"/admin/tasks/{deleted_task['id']}",
        headers=make_auth_headers(admin_login),
    )

    assert response.status_code == 204
    assert response.content == b""

    # Persistence testing (side effect)
    assert db_session.get(Task, deleted_task["id"]) is None
    track_created_tasks.discard(deleted_task["id"])
    assert task_state(
        db_session.get(Task, kept_task["id"])) == kept_task_before
    assert user_state(db_session.get(User, new_user["id"])) == user_before


@pytest.mark.task_count(1)
def test_delete_task_nonexistent(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    new_tasks,
):
    missing_task_id = -1
    assert db_session.get(Task, missing_task_id) is None
    before = snapshot_all(db_session)

    response = client.delete(
        f"/admin/tasks/{missing_task_id}",
        headers=make_auth_headers(admin_login),
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Task not found"}
    assert snapshot_all(db_session) == before


# ---------------- PATCH /admin/users/{user_id} ----------------


@pytest.mark.task_count(1)
def test_update_user(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    new_tasks,
    user_data,
):
    admin_before = user_state(db_session.get(User, new_admin_user["id"]))
    task_before = task_state(db_session.get(Task, new_tasks[0]["id"]))

    response = client.patch(
        f"/admin/users/{new_user['id']}",
        headers=make_auth_headers(admin_login),
        json=PATCH_BODY,
    )

    assert response.status_code == 200

    # Public contract testing
    assert response.json() == {
        **new_user,
        "is_active": False,
        "is_admin": True,
    }

    # Persistence testing (side effect): modified and unmodified fields
    user = db_session.get(User, new_user["id"])
    assert user is not None
    assert_user_response(response.json(), user)
    assert user.username == user_data["username"].lower()
    assert user.email == user_data["email"].lower()
    assert user.is_active is False
    assert user.is_admin is True
    assert user.password_hash != user_data["password"]
    matches, _ = verify_password(user_data["password"], user.password_hash)
    assert matches
    assert user_state(
        db_session.get(User, new_admin_user["id"])) == admin_before
    assert task_state(db_session.get(Task, new_tasks[0]["id"])) == task_before


@pytest.mark.task_count(1)
def test_update_user_partial(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    new_tasks,
):
    # Only the sent field changes
    response = client.patch(
        f"/admin/users/{new_user['id']}",
        headers=make_auth_headers(admin_login),
        json={"is_admin": True},
    )

    assert response.status_code == 200
    assert response.json() == {**new_user, "is_active": True, "is_admin": True}
    user = db_session.get(User, new_user["id"])
    assert user.is_active is True
    assert user.is_admin is True


@pytest.mark.task_count(1)
def test_update_user_self(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    new_tasks,
):
    before = snapshot_all(db_session)

    response = client.patch(
        f"/admin/users/{new_admin_user['id']}",
        headers=make_auth_headers(admin_login),
        json={"is_admin": False, "is_active": False},
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Admin user cannot update their own permissions"}
    assert snapshot_all(db_session) == before
    admin = db_session.get(User, new_admin_user["id"])
    assert admin.is_admin is True
    assert admin.is_active is True


@pytest.mark.task_count(1)
def test_update_user_nonexistent(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    new_tasks,
):
    missing_user_id = -1
    assert db_session.get(User, missing_user_id) is None
    before = snapshot_all(db_session)

    response = client.patch(
        f"/admin/users/{missing_user_id}",
        headers=make_auth_headers(admin_login),
        json=PATCH_BODY,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}
    assert snapshot_all(db_session) == before


@pytest.mark.task_count(1)
@pytest.mark.parametrize("body", [
    pytest.param({}, id="empty"),
    pytest.param({"is_active": None, "is_admin": None}, id="all_null"),
    pytest.param({"is_admin": "maybe"}, id="not_a_bool"),
    pytest.param({"is_admin": True, "username": "hacked"}, id="extra_field"),
])
def test_update_user_invalid_body(
    db_session,
    client,
    new_admin_user,
    admin_login,
    new_user,
    new_tasks,
    body,
):
    before = snapshot_all(db_session)

    response = client.patch(
        f"/admin/users/{new_user['id']}",
        headers=make_auth_headers(admin_login),
        json=body,
    )

    assert response.status_code == 422
    assert isinstance(response.json()["detail"], list)
    assert snapshot_all(db_session) == before
