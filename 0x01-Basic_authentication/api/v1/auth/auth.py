#!/usr/bin/env python3
"""Base authentication class"""
from flask import request
from typing import List, TypeVar


class Auth():
    """Base authentication class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Define which paths in the api require authentication
        Parameters:
            - Path: string representing an api route path
            - excluded_paths: List of paths that dont require authentication
        Return:
            False if @path in the list of @excluded_paths
            True otherwise
        """
        if path is None:
            return True
        if excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != '/':
            path = path + '/'
        if path in excluded_paths:
            return False
        else:
            return True

    def authorization_header(self, request=None) -> str:
        """get an authorization response header"""
        if request is None:
            return None
        auth_type = request.headers.get('Authorization', None)
        return None if auth_type is None else auth_type

    def current_user(self, request=None) -> TypeVar('User'):
        """Get the current user"""
        return None
