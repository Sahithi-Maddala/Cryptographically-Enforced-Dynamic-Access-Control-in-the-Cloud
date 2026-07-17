# utils_wrapped_keys.py
import json
import base64
import os

WRAPPED_KEYS_FILE = "wrapped_keys.json"

def _load():
    if not os.path.exists(WRAPPED_KEYS_FILE):
        return {}
    with open(WRAPPED_KEYS_FILE, "r") as f:
        return json.load(f)

def _save(data):
    with open(WRAPPED_KEYS_FILE, "w") as f:
        json.dump(data, f, indent=4)

def save_wrapped_key(filename, user_email, wrapped_key: bytes):
    data = _load()
    data.setdefault(filename, {})
    data[filename][user_email] = base64.b64encode(wrapped_key).decode()
    _save(data)

def load_wrapped_key(filename, user_email) -> bytes:
    data = _load()
    return base64.b64decode(data[filename][user_email])

def revoke_user(filename, user_email):
    data = _load()
    if filename in data and user_email in data[filename]:
        del data[filename][user_email]
        _save(data)
