#!/usr/bin/env python3
"""Basic session auth class"""
from typing import TypeVar
from api.v1.auth.auth import Auth
from models.user import User
import uuid


class SessionAuth(Auth):
    """Implement basic session auth mechanisms"""

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Create a session id"""
        if user_id is None:
            return None
        if type(user_id) is not str:
            return None
        session_id = str(uuid.uuid4())
        SessionAuth.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Get user_id associated with @session_id"""
        if session_id is None:
            return None
        if type(session_id) is not str:
            return None
        uid = SessionAuth.user_id_by_session_id.get(session_id, None)
        return uid

    def current_user(self, request=None) -> TypeVar('User'):
        """get a user id from a session cookie"""
        cookie_val = self.session_cookie(request)
        user_id = self.user_id_for_session_id(cookie_val)
        return User.get(user_id)

    def destroy_session(self, request=None) -> bool:
        """delete user session"""
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if session_id is None:
            return False
        uid = self.user_id_for_session_id(session_id)
        if uid is None:
            return False
        del SessionAuth.user_id_by_session_id[session_id]
        return True
