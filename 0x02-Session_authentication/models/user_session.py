#!/usr/bin/env python3
""" UserSession module
"""

from models.base import Base


class UserSession(Base):
    """Model a userSession database storage model"""

    def __init__(self, *args: list, **kwargs: dict):
        """Initialize the class
        and set user_id and session_id"""
        super().__init__(args, kwargs)
        self.user_id = kwargs.get('user_id')
        self.session_id = kwargs.get('session_id')
