"""
Kensa's PBKDF2 extended api key hasher.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import base64
import hashlib
import os

from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.utils.crypto import pbkdf2


class KensaApiKeyHasher(PBKDF2PasswordHasher):
    """Extends from PBKDF2PasswordHasher but avoids,
    disclosing algorithm used to encode the secret."""


    salt = os.getenv("KENSA_API_KEY_SALT", "fuZ0")


    def encode(self, api_key):
        """Encode the secret"""
        key = pbkdf2(api_key, self.salt, self.iterations, digest=self.digest)
        key = base64.b64encode(key).decode('ascii').strip()
        return "%s%s" % (self.salt, key)


    def verify(self):
        """Method not implemented"""
        return None


