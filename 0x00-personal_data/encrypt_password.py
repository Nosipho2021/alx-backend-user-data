#!/usr/bin/env python3
"""Encrypting passwords with bcrypt."""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password string.

    Takes a string argument, converts it to a byte string,
    and returns the salted, hashed password as a byte string.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against a hashed password.

    Checks if the provided password matches the hashed password.
    Returns a boolean value.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
