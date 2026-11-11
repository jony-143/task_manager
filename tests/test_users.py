from config import settings
from datetime import timedelta
from sqlalchemy import select

from models import User
from security import verify_password, create_access_token
from tests.helpers import make_auth_headers
from tests.token_factory import make_token


def test_make_token_sanity_check(db_session, client, new_user, user_data, track_created_users):
    # Checking if my make_token (used for creating bad tokens) is building valid tokens
    token = make_token(sub=user_data["username"])
    user_id = new_user["id"]
    auth_headers = {"Authorization": f"Bearer {token}"}
    r = client.request(
        "DELETE",
        "/users/me",
        json={"password": user_data["password"]},
        headers=auth_headers,
    )
    assert r.status_code == 204
    assert r.content == b""

    # Persistence testing (side effect)
    user = db_session.get(User, user_id)
    assert user is None
    track_created_users.discard(user_id)


# register_user

def test_register_user(db_session, client, user_data, track_created_users):
    # Positive case for registering a new user
    r = client.post("/users/", json=user_data)

    assert r.status_code == 201
    data = r.json()
    track_created_users.add(data["id"])

    # Public contract testing
    assert set(data) == {"id", "username", "email"}
    assert isinstance(data["id"], int)
    assert data["username"] == user_data["username"].lower()
    assert data["email"] == user_data["email"].lower()

    # Persistence testing (side effect)
    user = db_session.get(User, data["id"])
    assert user is not None
    assert user.username == user_data["username"].lower()
    assert user.email == user_data["email"].lower()
    assert user.is_active
    assert not user.is_admin
    assert user.password_hash != user_data["password"]
    matches, _ = verify_password(user_data["password"], user.password_hash)
    assert matches


def test_register_user_taken_1(db_session, client, new_user, user_data):
    # Attempt to register the same email again
    data = {**user_data, "username": user_data["username"]+"1"}
    r = client.post("/users/", json=data)
    assert r.status_code == 409

    # Database state should remain unchanged
    user = db_session.get(User, new_user["id"])
    assert user is not None
    assert user.username == user_data["username"].lower()
    assert user.email == user_data["email"].lower()
    assert user.is_active
    assert not user.is_admin
    assert user.password_hash != user_data["password"]
    matches, _ = verify_password(user_data["password"], user.password_hash)
    assert matches


def test_register_user_taken_2(db_session, client, new_user, user_data):
    # Attempt to register the same username again
    data = {**user_data, "email": "1"+user_data["email"]}
    r = client.post("/users/", json=data)
    assert r.status_code == 409

    # Database state should remain unchanged
    user = db_session.get(User, new_user["id"])
    assert user is not None
    assert user.username == user_data["username"].lower()
    assert user.email == user_data["email"].lower()
    assert user.is_active
    assert not user.is_admin
    assert user.password_hash != user_data["password"]
    matches, _ = verify_password(user_data["password"], user.password_hash)
    assert matches


def test_register_user_taken_3(db_session, client, new_user, user_data):
    # Attempt to register the same username and email again
    data = user_data
    r = client.post("/users/", json=data)
    assert r.status_code == 409

    # Database state should remain unchanged
    user = db_session.get(User, new_user["id"])
    assert user is not None
    assert user.username == user_data["username"].lower()
    assert user.email == user_data["email"].lower()
    assert user.is_active
    assert not user.is_admin
    assert user.password_hash != user_data["password"]
    matches, _ = verify_password(user_data["password"], user.password_hash)
    assert matches

# TODO: Testing input validation and edge cases

# delete_user


def test_delete_user(db_session, client, new_user, login, user_data, track_created_users):
    user_id = new_user["id"]
    auth_headers = {"Authorization": f"Bearer {login['access_token']}"}
    r = client.request(
        "DELETE",
        "/users/me",
        json={"password": user_data["password"]},
        headers=auth_headers,
    )
    assert r.status_code == 204
    assert r.content == b""

    # Persistence testing (side effect)
    user = db_session.get(User, user_id)
    assert user is None
    track_created_users.discard(user_id)


def test_delete_user_wrong_password(db_session, client, new_user, login, user_data):
    # Attempt to delete the user with the wrong password in re-authentication
    auth_headers = {"Authorization": f"Bearer {login['access_token']}"}
    r = client.request(
        "DELETE",
        "/users/me",
        json={"password": "wrong_password"},
        headers=auth_headers,
    )
    assert r.status_code == 401
    assert r.headers.get("www-authenticate") == "Bearer"
    assert r.json() == {"detail": "Could not validate credentials"}

    # Database state should remain unchanged
    user = db_session.get(User, new_user["id"])
    assert user is not None
    assert user.username == user_data["username"].lower()
    assert user.email == user_data["email"].lower()
    assert user.is_active
    assert not user.is_admin
    assert user.password_hash != user_data["password"]
    matches, _ = verify_password(user_data["password"], user.password_hash)
    assert matches


def test_delete_user_bad_tokens(db_session, client, new_user, make_bad_token, user_data):
    auth_headers = make_bad_token(user_data["username"])
    r = client.request(
        "DELETE",
        "/users/me",
        json={"password": user_data["password"]},
        headers=auth_headers,
    )
    assert r.status_code == 401
    assert r.json() == {
        "detail": (
            "Could not validate credentials"
            if auth_headers.get("Authorization", "").split(" ", 1)[0] == "Bearer"
            else "Not authenticated"
        )
    }
    assert r.headers.get("www-authenticate") == "Bearer"

    # Database state should remain unchanged
    user = db_session.get(User, new_user["id"])
    assert user is not None
    assert user.username == user_data["username"].lower()
    assert user.email == user_data["email"].lower()
    assert user.is_active
    assert not user.is_admin
    assert user.password_hash != user_data["password"]
    matches, _ = verify_password(user_data["password"], user.password_hash)
    assert matches


def test_delete_user_inactive(db_session, client, new_user, login, user_data, set_inactive_user):
    # Set the user as inactive
    set_inactive_user(new_user["id"])

    # Attempt to delete the inactive user
    auth_headers = {"Authorization": f"Bearer {login['access_token']}"}
    r = client.request(
        "DELETE",
        "/users/me",
        json={"password": user_data["password"]},
        headers=auth_headers,
    )
    assert r.status_code == 403
    assert r.json() == {"detail": "Inactive user"}

    # Database state should remain unchanged
    user = db_session.get(User, new_user["id"])
    assert user is not None
    assert user.username == user_data["username"].lower()
    assert user.email == user_data["email"].lower()
    assert not user.is_active
    assert not user.is_admin
    assert user.password_hash != user_data["password"]
    matches, _ = verify_password(user_data["password"], user.password_hash)
    assert matches


def test_delete_user_admin(db_session, client, new_admin_user, admin_login,
                           admin_data, track_created_users):
    # Attempt to delete the admin user
    auth_headers = {"Authorization": f"Bearer {admin_login['access_token']}"}
    r = client.request(
        "DELETE",
        "/users/me",
        json={"password": admin_data["password"]},
        headers=auth_headers,
    )

    assert r.status_code == 204
    assert r.content == b""

    # Persistence testing (side effect)
    user = db_session.get(User, new_admin_user["id"])
    assert user is None
    track_created_users.discard(new_admin_user["id"])
