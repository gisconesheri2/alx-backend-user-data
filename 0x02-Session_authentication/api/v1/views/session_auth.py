#!/usr/bin/env python3
""" Module of Users views
"""
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
import os


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_login():
    """get user from a session"""
    user_email = request.form.get('email', None)
    user_pswd = request.form.get('password', None)

    if user_email is None:
        return jsonify({"error": "email missing"}), 400
    if user_pswd is None:
        return jsonify({"error": "password missing"}), 400

    user = User.search({'email': user_email})
    if len(user) == 0:
        return jsonify({"error": "no user found for this email"}), 404
    u_one = user[0]
    if u_one.is_valid_password(user_pswd) is False:
        return jsonify({"error": "wrong password"}), 401

    from api.v1.app import auth
    session_id = auth.create_session(u_one.id)
    sess_name = os.getenv('SESSION_NAME')
    out = jsonify(u_one.to_json())
    out.set_cookie(sess_name, session_id)
    return out


@app_views.route('/auth_session/logout',
                 methods=['DELETE'], strict_slashes=False)
def session_logout():
    """delete a session id"""

    from api.v1.app import auth
    ds = auth.destroy_session(request)
    if ds is False:
        abort(404)
    return jsonify({}), 200
