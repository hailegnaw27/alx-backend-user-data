#!/usr/bin/env python3
"""Authentication module for managing access control.
"""
import re
from typing import List, TypeVar
from flask import request


class Auth:
    """Base class for handling authentication processes.
    """
    
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determine if a specific path requires authentication.
        
        Args:
            path (str): The path to check.
            excluded_paths (List[str]): A list of paths that do not require authentication.
            
        Returns:
            bool: True if the path requires authentication, False otherwise.
        """
        if path is not None and excluded_paths is not None:
            for exclusion_path in map(lambda x: x.strip(), excluded_paths):
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
        if request is not None:
            return request.headers.get('Authorization', None)
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

