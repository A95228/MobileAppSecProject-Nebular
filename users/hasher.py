"""
Kensa's extended api key hasher.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import base64
import hashlib
import os

from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.utils.crypto import (constant_time_compare, pbkdf2,)


class KensaApiKeyHasher(PBKDF2PasswordHasher):
    """Extends from PBKDF2PasswordHasher but avoids,
    disclosing algorithm used to encode the secret."""

    salt = os.getenv("KENSA_API_KEY_SALT", "fuZ0")


    def encode(self, api_key):
        """Encode an api_key"""
        hash = pbkdf2(api_key, self.salt, self.iterations, digest=self.digest)
        hash = base64.b64encode(hash).decode('ascii').strip()
        return "%s%s" % (self.salt, hash)


    def verify(self, api_key, encoded):
        """Verify the api_key"""
        encoded_2 = self.encode(api_key)
        return constant_time_compare(encoded, encoded_2)
		


