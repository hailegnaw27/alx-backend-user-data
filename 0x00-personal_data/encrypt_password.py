#!/usr/bin/env python3
"""
Module for password hashing and validation
"""

import bcrypt
from typing import Union

def hash_password(password: str) -> bytes:
    """
    Hash a password with a random salt using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The salted, hashed password.
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validate a password against its hashed version.

    Args:
        hashed_password (bytes): The hashed password.
        password (str): The password to validate.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)

