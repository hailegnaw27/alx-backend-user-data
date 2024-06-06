#!/usr/bin/env python3
"""Session management for authentication.
"""
from uuid import uuid4
from flask import request

from .auth import Auth
from models.user import User

class SessionAuth(Auth):
    """Session management class for user authentication.
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Generate a new session ID for a user.

        Args:
            user_id (str): The user ID for which the session is created.

        Returns:
            str: The newly created session ID.
        """
        if isinstance(user_id, str):
            session_id = str(uuid4())
            self.user_id_by_session_id[session_id] = user_id
            return session_id
        return None

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Retrieve the user ID associated with a given session ID.

        Args:
            session_id (str): The session ID to look up.

        Returns:
            str: The user ID associated with the session ID, or None if not found.
        """
        if isinstance(session_id, str):
            return self.user_id_by_session_id.get(session_id)
        return None

    def current_user(self, request=None) -> User:
        """
        Retrieve the current user based on the session ID in the request.

        Args:
            request (flask.Request, optional): The request object containing the session cookie.

        Returns:
            User: The User object associated with the session ID, or None if not found.
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        if user_id:
            return User.get(user_id)
        return None

    def destroy_session(self, request=None) -> bool:
        """
        Destroy the session associated with the request.

        Args:
            request (flask.Request, optional): The request object containing the session cookie.

        Returns:
            bool: True if the session was successfully destroyed, False otherwise.
        """
        session_id = self.session_cookie(request)
        if request is None or session_id is None:
            return False
        if session_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[session_id]
            return True
        return False

