"""
This module contains validators for the User API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import re
import pdb

from django.contrib.auth.password_validation import CommonPasswordValidator
from django.contrib.auth.validators import (
    ASCIIUsernameValidator,
    UnicodeUsernameValidator
)
from django.core.exceptions import ValidationError

from . import models


common = CommonPasswordValidator()


def validate_password(value, length=8): # tested
    """Somewhat strict validator, returns True once all 
    test cases pass, raises a ValidationError if it fails a test."""

    if not isinstance(length, int): # for developers only
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


def validate_email(email):
    """Check if email is taken."""
    try:
        models.User.objects.get(email=email)
    except:
        return True
    raise ValidationError(
                'A user with that email already exists.') from None


def validate_username(username):
    """Check if username is taken"""
    try:
        models.User.objects.get(username=username)
    except:
        return True
    raise ValidationError(
            "A user with that username already exists") from None


def validate_api_key(api_key):
    """Check if user with api key does not exists"""
    try:
        models.User.objects.get(api_key=api_key)
    except:
        return True
    raise ValidationError(
            "api_key is already taken, try again.") from None
