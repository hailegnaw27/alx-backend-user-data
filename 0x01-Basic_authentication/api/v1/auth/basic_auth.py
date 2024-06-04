#!/usr/bin/env python3
"""Basic Authentication Implementation.
"""
import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Class for handling Basic Authentication.
    """
    
    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """
        Extract the Base64 part of the Authorization header.
        
        Args:
            authorization_header (str): The Authorization header from the request.
            
        Returns:
            str: The Base64 encoded token, or None if not found.
        """
        if isinstance(authorization_header, str):
            pattern = r'Basic (?P<token>.+)'
            match = re.fullmatch(pattern, authorization_header.strip())
            if match:
                return match.group('token')
        return None

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """
        Decode the Base64 encoded Authorization header.
        
        Args:
            base64_authorization_header (str): The Base64 encoded token.
            
        Returns:
            str: The decoded value as a UTF-8 string, or None if decoding fails.
        """
        if isinstance(base64_authorization_header, str):
            try:
                decoded_bytes = base64.b64decode(base64_authorization_header, validate=True)
                return decoded_bytes.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """
        Extract user credentials from the decoded Base64 string.
        
        Args:
            decoded_base64_authorization_header (str): The decoded Base64 string.
            
        Returns:
            Tuple[str, str]: The user's email and password, or (None, None) if extraction fails.
        """
        if isinstance(decoded_base64_authorization_header, str):
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            match = re.fullmatch(pattern, decoded_base64_authorization_header.strip())
            if match:
                user = match.group('user')
                password = match.group('password')
                return user, password
        return None, None

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
        Retrieve the user object using email and password.
        
        Args:
            user_email (str): The user's email.
            user_pwd (str): The user's password.
            
        Returns:
            TypeVar('User'): The User object if credentials are valid, or None otherwise.
        """
        if isinstance(user_email, str) and isinstance(user_pwd, str):
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if not users:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieve the current user based on the request's Authorization header.
        
        Args:
            request (flask.Request, optional): The Flask request object.
            
        Returns:
            TypeVar('User'): The authenticated User object, or None if authentication fails.
        """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)

