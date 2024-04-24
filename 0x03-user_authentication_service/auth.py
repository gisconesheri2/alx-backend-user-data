#!/usr/bin/env python3
"""Auth module
"""
from db import DB
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from typing import TypeVar
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """hash a password with bcrypt"""
    pss_bytes = bytes(password, encoding='utf-8')
    hashed = bcrypt.hashpw(pss_bytes, bcrypt.gensalt())
    return hashed


def _generate_uuid(self) -> str:
    """generate a uuid"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initialize class"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> TypeVar('User'):
        """register a user with given email"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError('User {} already exists'.format(email))
        except NoResultFound:
            hashed = _hash_password(password)
            return self._db.add_user(email, hashed)

    def valid_login(self, email: str, password: str) -> bool:
        """Verify password login"""
        try:
            user = self._db.find_user_by(email=email)
            pss_bytes = bytes(password, encoding='utf-8')
            if bcrypt.checkpw(pss_bytes, user.hashed_password):
                return True
            else:
                return False
        except NoResultFound:
            return False

    def create_session(self, email) -> str:
        """create and store a session id"""
        try:
            user = self._db.find_user_by(email=email)
            sess_id = _generate_uuid()
            self._db.update_user(user.id, session_id=sess_id)
            return sess_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> TypeVar('User'):
        """get a user with associated session_id"""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Remove a session id associated with user_id"""
        try:
            self._db.update_user(user_id, **{'session_id': None})
            return None
        except ValueError:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """generate a password reset token"""
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, **{'reset_token': reset_token})
            return reset_token
        except NoResultFound:
            raise ValueError()

    def update_password(self, reset_token: str, password: str) -> None:
        """update a password for account associated with the reset token"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_pwd = _hash_password(password)
            self._db.update_user(user.id, **{'hashed_password': hashed_pwd})
            self._db.update_user(user.id, **{'reset_token': None})
        except NoResultFound:
            raise ValueError()
