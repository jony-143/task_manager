def make_auth_headers(login):
    return {"Authorization": f"Bearer {login['access_token']}"}
