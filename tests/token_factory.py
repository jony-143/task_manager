from datetime import datetime, timedelta, timezone
import jwt
import json
import base64
from config import settings


def make_token(
    *,
    sub="default_user",
    exp_delta=timedelta(minutes=5),
    key=settings.SECRET_KEY,
    algo=settings.ALGORITHM,
    extra=None,
    drop=(),
):
    payload = {"sub": sub, "exp": datetime.now(timezone.utc) + exp_delta}
    payload.update(extra or {})
    for claim in drop:
        payload.pop(claim, None)
    encoded_jwt = jwt.encode(payload=payload, key=key, algorithm=algo)
    return encoded_jwt


def tamper_token(token, new_sub):
    header, payload, signature = token.split(".")
    padding = "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload + padding))
    claims["sub"] = new_sub
    changed_payload = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{changed_payload}.{signature}"


BAD_TOKENS = {
    "non_existent_user": lambda sub: make_token(sub="non_existent_user"),
    "no_sub": lambda sub: make_token(sub=sub, drop=("sub",)),
    "no_exp": lambda sub: make_token(sub=sub, drop=("exp",)),
    "exp_string": lambda sub: make_token(sub=sub, extra={"exp": "never"}),
    "expired": lambda sub: make_token(sub=sub, exp_delta=timedelta(seconds=-10)),
    "wrong_key": lambda sub: make_token(sub=sub, key="not-the-real-secret-key-0123456789"),
    "wrong_alg": lambda sub: make_token(sub=sub, algo="HS512", key=settings.SECRET_KEY),
    "no_signature": lambda sub: make_token(sub=sub, key="", algo="none"),
    "tampered": lambda sub: tamper_token(make_token(sub="another_user"), new_sub=sub),
    "garbage": lambda sub: "not.a.jwt",
}


def _bearer(token_fn):
    return lambda sub: {"Authorization": f"Bearer {token_fn(sub)}"}


BAD_HEADERS = {
    **{f"token_{n}": _bearer(fn) for n, fn in BAD_TOKENS.items()},
    "no_header": lambda sub: {},
    "wrong_scheme": lambda sub: {"Authorization": f"Token {make_token(sub=sub)}"},
    "scheme_only": lambda sub: {"Authorization": "Bearer"},
    "empty_token": lambda sub: {"Authorization": "Bearer "},
    "empty_token_2": lambda sub: {"Authorization": "Bearer  "},
}
