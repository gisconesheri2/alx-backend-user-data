#!/usr/bin/env python3
"""Basic session auth class with expiry"""
from typing import TypeVar
from api.v1.auth.session_auth import SessionAuth
from os import getenv
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """Implent expiry for a session"""

    def __init__(self):
        """Get and set the session expiry duration"""
        super().__init__()
        sess_exp = getenv('SESSION_DURATION')
        if sess_exp is None:
            self.session_duration = 0
        try:
            self.session_duration = int(sess_exp)
        except Exception:
            self.session_duration = 0

    def create_session(self, user_id: str = None) -> str:
        """Create a session id and store it in memory"""
        sess_id = super().create_session(user_id)
        if sess_id is None:
            return None
        sess_dict = {}
        sess_dict['user_id'] = user_id
        sess_dict['created_at'] = datetime.now()
        self.user_id_by_session_id[sess_id] = sess_dict
        return sess_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Get a user_id associtated with session_id"""
        if session_id is None:
            return None
        sess_dict = self.user_id_by_session_id.get(session_id, None)
        if sess_dict is None:
            return None
        if self.session_duration <= 0:
            return sess_dict['user_id']
        if 'created_at' in sess_dict is False:
            return None
        created_at = sess_dict.get('created_at')
        if (datetime.now() >
                created_at + timedelta(seconds=self.session_duration)):
            return None
        return sess_dict['user_id']
