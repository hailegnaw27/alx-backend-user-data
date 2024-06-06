#!/usr/bin/env python3
"""Authentication module for managing user access.
"""
import os
import re
from typing import List, TypeVar
from flask import request

class Auth:
    """Class for handling user authentication.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determine if a given path requires authentication.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): A list of paths that do not require authentication.

        Returns:
            bool: True if the path requires authentication, False otherwise.
        """
        if path and excluded_paths:
            for exclusion_path in map(str.strip, excluded_paths):
                pattern = ''
                if exclusion_path.endswith('*'):
                    pattern = '{}.*'.format(exclusion_path[:-1])
                elif exclusion_path.endswith('/'):
                    pattern = '{}/*'.format(exclusion_path[:-1])
                else:
                    pattern = '{}/*'.format(exclusion_path)
                if re.match(pattern, path):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieve the Authorization header from the request.

        Args:
            request (flask.Request, optional): The Flask request object.

        Returns:
            str: The value of the Authorization header, or None if not present.
        """
        if request:
            return request.headers.get('Authorization')
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieve the current user based on the request.

        Args:
            request (flask.Request, optional): The Flask request object.

        Returns:
            TypeVar('User'): The current user, or None if not authenticated.
        """
        return None

    def session_cookie(self, request=None) -> str:
        """
        Retrieve the session cookie from the request.

        Args:
            request (flask.Request, optional): The Flask request object.

        Returns:
            str: The value of the session cookie, or None if not present.
        """
        if request:
            cookie_name = os.getenv('SESSION_NAME')
            return request.cookies.get(cookie_name)
        return None

