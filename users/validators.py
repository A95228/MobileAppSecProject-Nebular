"""
This module contains validators for the User API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import re
import pdb

from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import CommonPasswordValidator

from . import models


common = CommonPasswordValidator()


def validate_password(value, length=8): # tested
    """Somewhat strict validator, returns True once all 
    test cases pass, raises a ValidationError if it fails a test."""

    if not isinstance(lenght, int) # for developers only
        raise Exception("Length param must be of type int") 

    if value in common.passwords:
        raise ValidationError(
            "Password is a common password, vulnerable to brute force attacks."
        ) from None

    if len(value) < length:
        raise ValidationError(
            'Password must be %s chars or more.' % length) from None

    elif len(re.findall(r'\W', value)) == 0:
        raise ValidationError(
            'Password must include special characters.') from None

    elif len(re.findall(r'[A-Z]', value)) == 0:
        raise ValidationError(
            'Password must include uppercase letters.') from None

    elif len(re.findall(r'[a-z]', value)) == 0:
        raise ValidationError(
            'Password must include lowercase letters.') from None

    elif len(re.findall(r'[0-9]', value)) == 0:
        raise ValidationError(
            'Password must include digits.') from None

    return True


def validate_not_taken_email(email):
    """Validate if email is taken, returns green if it's ok to update 
    the email with the param value"""
    if models.User.objects.get(email=email).exists():
        raise ValidationError(
                'A user with that email already exists.') from None
    return True


def validate_username(username):
    """Validate if username is taken, raises ValidationError is User 
    with username exists, otherwise returns green."""
    if models.User.objects.get(username=username).exists():
        raise ValidationError(
            "A user with that username already exists") from None
    return True


def validate_api_key(api_key):
    """Validate a fresh out of the function api_key for a fresh user"""
    if models.User.objects.get(api_key=api_key).exists():
        raise ValidationError(
            "api_key is already taken, try again.") from None
    return True

