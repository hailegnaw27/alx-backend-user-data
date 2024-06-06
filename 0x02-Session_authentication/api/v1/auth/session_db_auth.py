#!/usr/bin/env python3
"""Session management with database persistence.
"""
from flask import request
from datetime import datetime, timedelta

from models.user_session import UserSession
from .session_exp_auth import SessionExpAuth

class SessionDBAuth(SessionExpAuth):
    """Session authentication class with database storage.
    """

    def create_session(self, user_id=None) -> str:
        """
        Create and store a new session ID in the database.

        Args:
            user_id (str): The ID of the user for whom the session is created.

        Returns:
            str: The created session ID.
        """
        session_id = super().create_session(user_id)
        if isinstance(session_id, str):
            user_session = UserSession(user_id=user_id, session_id=session_id)
            user_session.save()
            return session_id
        return None

    def user_id_for_session_id(self, session_id=None):
        """
        Retrieve the user ID associated with a given session ID from the database.

        Args:
            session_id (str): The session ID to look up.

        Returns:
            str: The user ID associated with the session ID, or None if not found or expired.
        """
        if not isinstance(session_id, str):
            return None

        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return None
        
        if not sessions:
            return None

        session = sessions[0]
        cur_time = datetime.now()
        exp_time = session.created_at + timedelta(seconds=self.session_duration)
        if exp_time < cur_time:
            return None

        return session.user_id

    def destroy_session(self, request=None) -> bool:
        """
        Destroy the session associated with the request.

        Args:
            request (flask.Request, optional): The request object containing the session cookie.

        Returns:
            bool: True if the session was successfully destroyed, False otherwise.
        """
        session_id = self.session_cookie(request)
        if not isinstance(session_id, str):
            return False

        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return False
        
        if not sessions:
            return False

        session = sessions[0]
        session.remove()
        return True

