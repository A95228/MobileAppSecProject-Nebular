"""
This file holds validators for the User API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import re
import pdb

from django.contrib.auth.password_validation import CommonPasswordValidator
from django.contrib.auth.validators import (
    ASCIIUsernameValidator,
    UnicodeUsernameValidator
)
from django.core.exceptions import ValidationError
from django import forms

from users import models


common = CommonPasswordValidator()

def is_email(email):
    """Verifies if the field is an email"""
    try:
        forms.EmailField().clean(email)
    except ValidationError:
        raise ValidationError("Invalid email.") from None


def validate_password(value, length=8): # tested
    """Somewhat strict validator, returns True once all 
    test cases pass, raises a ValidationError if it fails a test."""

    if not isinstance(length, int): # for developers only
        raise Exception("Length param must be of type int") 

    if value in common.passwords:
        raise ValidationError(
            "Password is a common password, vulnerable to brute force attacks."
        )

    if len(value) < length:
        raise ValidationError(
            'Password must be %s chars or more.' % length)

    elif len(re.findall(r'\W', value)) == 0:
        raise ValidationError(
            'Password must include special characters.')

    elif len(re.findall(r'[A-Z]', value)) == 0:
        raise ValidationError(
            'Password must include uppercase letters.')

    elif len(re.findall(r'[a-z]', value)) == 0:
        raise ValidationError(
            'Password must include lowercase letters.')

    elif len(re.findall(r'[0-9]', value)) == 0:
        raise ValidationError(
            'Password must include digits.')

    return True



def validate_email(email):
    """Check if email is taken."""
    is_email(email)
    if models.User.objects.filter(email=email).exists():
        raise ValidationError(
            'A user with that email already exists.') from None
    return True



def validate_username(username):
    """Check if username is taken"""
    if models.User.objects.filter(username=username).exists():
        raise ValidationError(
            'A user with that email already exists.') from None
    return True
    


def validate_api_key(api_key):
    """Check if user with api key does not exists"""
    if models.User.objects.filter(api_key=api_key).exists():
        raise ValidationError(
            'A user with that email already exists.') from None
    return True


