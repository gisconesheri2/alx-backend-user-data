#!/usr/bin/env python3
"""Test app"""

import requests
import json

URL = 'http://0.0.0.0:5000/'


def register_user(email: str, password: str) -> None:
    """Test registration of a user"""

    r = requests.post(f'{URL}users',
                      data={'email': email,
                            'password': password})
    msg = json.loads(r.text).get('message')
    try:
        assert msg == "user created"
    except AssertionError:
        assert msg == "email already registered"

    assert r.status_code == 200


def log_in_wrong_password(email: str, password: str) -> None:
    """Log in with wrong password"""
    r = requests.post(f'{URL}sessions',
                      data={'email': email,
                            'password': password})
    assert r.status_code == 401


def log_in(email: str, password: str) -> str:
    """Log in with correct password"""
    r = requests.post(f'{URL}sessions',
                      data={'email': email,
                            'password': password})

    msg = json.loads(r.text).get('message')
    session_id = r.cookies['session_id']

    assert r.status_code == 200
    assert msg == 'logged in'
    assert session_id is not None

    return session_id


def profile_unlogged() -> None:
    """Test an unlogged profile"""
    r = requests.get(f'{URL}profile')

    assert r.status_code == 403


def profile_logged(session_id: str) -> None:
    """test profile with a session id"""
    r = requests.get(f'{URL}profile', cookies={'session_id': session_id})
    email = r.json().get('email')

    assert email is not None
    assert r.status_code == 200


def log_out(session_id: str) -> None:
    """test profile with a session id"""
    r = requests.delete(f'{URL}sessions', cookies={'session_id': session_id})
    hist_resp = r.history[0]

    assert r.url == 'http://0.0.0.0:5000/'
    assert len(r.history) == 1
    assert hist_resp.url == 'http://0.0.0.0:5000/sessions'
    assert hist_resp.status_code == 302


def reset_password_token(email: str) -> str:
    """get a password reset token"""
    r = requests.post(f'{URL}reset_password',
                      data={'email': email})

    reset_token = r.json().get('reset_token')

    assert reset_token is not None
    assert r.status_code == 200

    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """update password using a reset token"""
    r = requests.put(f'{URL}reset_password',
                     data={'email': email,
                           'new_password': new_password,
                           'reset_token': reset_token})

    msg = r.json().get('message')

    assert msg == 'Password updated'
    assert r.status_code == 200


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
