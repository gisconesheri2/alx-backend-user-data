#!/usr/bin/env python3
"""Basic session auth class with expiry
with permanent storage"""
from typing import TypeVar
from models.user_session import UserSession
from api.v1.auth.session_exp_auth import SessionExpAuth


class SessionDBAuth(SessionExpAuth):
    """
    Basic session auth class with expiry
    with permanent storage
    """

    def __init__(self):
        """Initialize the parent class"""
        super().__init__()

    def create_session(self, user_id: str = None) -> str:
        """create a session id and create a new instance
        of usersession to store in a file"""
        sess_db_id = super().create_session(user_id)
        us = UserSession()
        us.user_id = user_id
        us.session_id = sess_db_id
        us.save()
        return sess_db_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Confirm session_id is present in the file
        If present, frun the super class logic"""
        try:
            sess_db_id = UserSession.search({'session_id': session_id})[0]
        except KeyError:
            return None

        if sess_db_id:
            return super().user_id_for_session_id(sess_db_id.session_id)
        return None

    def destroy_session(self, request=None) -> bool:
        """remove the session id from the file storage"""
        session_db_id = self.session_cookie(request)
        if session_db_id is None:
            return False
        sess_db_id = UserSession.search({'session_id': session_db_id})[0]
        sess_db_id.remove()
        super().destroy_session(request)
        return True
