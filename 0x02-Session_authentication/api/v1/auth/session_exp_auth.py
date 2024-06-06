#!/usr/bin/env python3
"""Session management with expiration feature.
"""
import os
from datetime import datetime, timedelta
from flask import request

from .session_auth import SessionAuth

class SessionExpAuth(SessionAuth):
    """Session management class with expiration handling.
    """

    def __init__(self) -> None:
        """Initialize the session with expiration.
        """
        super().__init__()
        try:
            self.session_duration = int(os.getenv('SESSION_DURATION', '0'))
        except ValueError:
            self.session_duration = 0

    def create_session(self, user_id=None) -> str:
        """
        Create a new session ID and store it with a timestamp.

        Args:
            user_id (str): The ID of the user for whom the session is created.

        Returns:
            str: The created session ID.
        """
        session_id = super().create_session(user_id)
        if not isinstance(session_id, str):
            return None
        self.user_id_by_session_id[session_id] = {
            'user_id': user_id,
            'created_at': datetime.now(),
        }
        return session_id

    def user_id_for_session_id(self, session_id=None) -> str:
        """
        Retrieve the user ID associated with a given session ID, considering expiration.

        Args:
            session_id (str): The session ID to look up.

        Returns:
            str: The user ID associated with the session ID, or None if expired or not found.
        """
        if session_id not in self.user_id_by_session_id:
            return None

        session_info = self.user_id_by_session_id[session_id]
        if self.session_duration <= 0:
            return session_info['user_id']
        
        if 'created_at' not in session_info:
            return None

        current_time = datetime.now()
        expiration_time = session_info['created_at'] + timedelta(seconds=self.session_duration)
        
        if current_time > expiration_time:
            return None

        return session_info['user_id']

