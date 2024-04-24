#!/usr/bin/env python3
"""Flask App module
"""

from flask import Flask, jsonify, request, abort, make_response, redirect
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'])
def home():
    """Home route for a simple flask app"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def users():
    """add user using the post data"""
    email = request.values.get('email')
    password = request.values.get('password')
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"})


@app.route('/sessions', methods=['POST'])
def login():
    """create a user session using the post data"""
    email = request.values.get('email')
    password = request.values.get('password')
    if AUTH.valid_login(email, password) is False:
        abort(401)
    sess_id = AUTH.create_session(email)
    if sess_id:
        resp = make_response(jsonify({"email": email, "message": "logged in"}))
        resp.set_cookie('session_id', sess_id)
        return resp


@app.route('/sessions', methods=['DELETE'])
def logout():
    """destroys/deletes a users session"""
    sess_id = request.cookies.get('session_id', None)
    if sess_id:
        user = AUTH.get_user_from_session_id(sess_id)
        if user:
            AUTH.destroy_session(user.id)
            return redirect('/')
        else:
            abort(403)


@app.route('/profile', methods=['GET'])
def profile():
    """return user details using the post data"""
    sess_id = request.cookies.get('session_id', None)
    if sess_id:
        user = AUTH.get_user_from_session_id(sess_id)
        if user:
            return jsonify({"email": user.email})
        else:
            abort(403)
    else:
        abort(403)


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token():
    """generate a reset token"""
    email = request.form.get('email')
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except ValueError:
        abort(403)


@app.route('/update_password', methods=['PUT'])
def update_password():
    """reset password"""
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_pass = request.form.get('new_password')
    try:
        AUTH.update_password(reset_token, new_pass)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
