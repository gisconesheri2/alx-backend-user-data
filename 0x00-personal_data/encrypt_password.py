#!/usr/bin/env python3
"""hash and decrypt passwords"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hash a password"""
    hash_pd = bcrypt.hashpw(password, bcrypt.gensalt())
    return hash_pd


def is_valid(hashed_password: bytes, password: str) -> bool:
    """check if a password is valid"""
    if bcrypt.checkpw(password, hashed_password):
        return True
    return False
