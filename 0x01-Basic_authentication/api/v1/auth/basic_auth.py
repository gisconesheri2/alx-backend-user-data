#!/usr/bin/env python3
"""Authentication module to handle basic authentication"""
import re
from api.v1.auth.auth import Auth
from models.user import User
import base64
from typing import TypeVar


class BasicAuth(Auth):
    """Handle logic for basic authentication
    """
    def __init__(self) -> None:
        """initialize the parent class"""
        super().__init__()

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Extract the base64 part of a Basic
        Authentication Header"""
        if authorization_header is None:
            return None
        if type(authorization_header) is not str:
            return None
        if authorization_header[0:6] != 'Basic ':
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str) -> str:  # noqa
        """
        decode a string from base64 to a utf-8 string
        """
        header_text = base64_authorization_header
        if header_text is None:
            return None
        if type(header_text) is not str:
            return None
        try:
            ht_b = bytes(header_text, 'utf-8')
            s = base64.b64decode(ht_b).decode('utf-8')
            return s
        except Exception as e:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str) -> (str, str):  # noqa
        """Get username and email from a decoded string"""
        auth_header_str = decoded_base64_authorization_header
        if auth_header_str is None:
            return (None, None)
        if type(auth_header_str) is not str:
            return (None, None)
        if ':' not in auth_header_str:
            return (None, None)
        match = re.search(r'([\w@.]+):(.*)', auth_header_str).groups()
        if match:
            return match
        else:
            return (None, None)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        authenticate a user based on the email and password
        and return an instance of them
        """
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        try:
            users = User.search({'email': user_email})
            if len(users) == 0:
                return None
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
                else:
                    return None
        except KeyError:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Get a current user by going through the authentication
        process"""
        header_text = self.authorization_header(request)
        ht_64 = self.extract_base64_authorization_header(header_text)
        ht_up = self.decode_base64_authorization_header(ht_64)
        user_email, user_pwd = self.extract_user_credentials(ht_up)
        user = self.user_object_from_credentials(user_email, user_pwd)
        return user
