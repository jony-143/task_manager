import jwt
from datetime import datetime, timezone
from config import settings


def test_auth_valid(client, new_user, user_data, task_data, track_created_tasks):
    r = client.post(
        "/auth/token",
        data={
            "username": user_data["email"],
            "password": user_data["password"]
        }
    )
    assert r.status_code == 200
    assert r.json().get("token_type") == "bearer"
    token = r.json().get("access_token")

    # Check token by decoding it
    decoded_payload = jwt.decode(
        jwt=token,
        key=settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"require": ["exp", "sub"], "verify_exp": True},
    )
    assert set(decoded_payload.keys()) == {"sub", "exp"}
    assert decoded_payload.get("sub") == user_data["username"]
    assert isinstance(decoded_payload.get("exp"), int)
    exp = datetime.fromtimestamp(decoded_payload["exp"], tz=timezone.utc)
    remaining = exp - datetime.now(timezone.utc)
    assert 0 < remaining.total_seconds() <= settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # Check token with APP
    response_create_task = client.post(
        "/tasks/",
        headers={"Authorization": f"Bearer {token}"},
        json=task_data
    )
    assert response_create_task.status_code == 201
    track_created_tasks.add(response_create_task.json()['id'])


def test_auth_invalid_username(client, new_user, user_data):
    r = client.post(
        "/auth/token",
        data={
            "username": "wrong_email@example.com",
            "password": user_data["password"]
        }
    )
    assert r.status_code == 401
    assert r.json().get("detail") == "Incorrect username or password"
    assert r.headers.get("www-authenticate") == "Bearer"


def test_auth_invalid_password(client, new_user, user_data):
    r = client.post(
        "/auth/token",
        data={
            "username": user_data["email"],
            "password": "wrong_password"
        }
    )
    assert r.status_code == 401
    assert r.json().get("detail") == "Incorrect username or password"
    assert r.headers.get("www-authenticate") == "Bearer"


def test_auth_missing_username(client, new_user, user_data):
    r = client.post(
        "/auth/token",
        data={
            "password": user_data["password"]
        }
    )
    assert r.status_code == 422


def test_auth_missing_password(client, new_user, user_data):
    r = client.post(
        "/auth/token",
        data={
            "username": user_data["email"]
        }
    )
    assert r.status_code == 422


def test_auth_inactive_user(client, new_user, user_data, set_inactive_user):
    set_inactive_user(new_user["id"])
    r = client.post(
        "/auth/token",
        data={
            "username": user_data["email"],
            "password": user_data["password"]
        }
    )
    assert r.status_code == 403
    assert r.json().get("detail") == "Inactive user"
