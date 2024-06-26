#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from user import Base, User
from typing import TypeVar, Dict


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db")
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> TypeVar('User'):
        """Add a user to the database"""
        new_user = User(email=email, hashed_password=hashed_password)
        try:
            self._session.add(new_user)
            self._session.commit()
        except Exception:
            self._session.rollback()
            raise
        return new_user

    def find_user_by(self, **kwargs: Dict) -> TypeVar('User'):
        """find user by supplied keyword"""
        try:
            user = self._session.query(User).filter_by(**kwargs).one()
        except NoResultFound:
            raise NoResultFound()
        except InvalidRequestError:
            raise InvalidRequestError()

        return user

    def update_user(self, user_id: int, **kwargs: Dict):
        """Update user with user_id with kwargs"""

        try:
            user = self.find_user_by(id=user_id)
        except NoResultFound:
            raise ValueError()

        for key, val in kwargs.items():
            if not (hasattr(user, key)):
                raise ValueError()
            setattr(user, key, val)

        try:
            self._session.commit()
        except InvalidRequestError:
            raise ValueError()
