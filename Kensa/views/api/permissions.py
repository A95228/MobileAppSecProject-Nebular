"""
Kensa's custom permissions.
~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import pdb
import re

from rest_framework import permissions


SYSTEMS = ["android", "ios"]
SYSTEMS_DROP = "Systems allowed: %s" % ", ".join(SYSTEMS)


class GETDataCheck(permissions.BasePermission):
    """Sanity check for parameters"""

    message = "Invalid parameters."

    def has_permission(self, request, view):
        """Sanity checks for some api get methods."""
        if request.method != "GET":
            self.message = "Methods allowed ~> GET"
            return False

        if request.GET.get("md5") is None:
            self.message = "Missing md5 parameter"
            return False

        if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
            self.message = "Invalid md5"
            return False

        return True


class HasAPIKey(permissions.BasePermission):
    """Custom permission to check if the user's api key is valid."""

    message = "Invalid api_key"

    def has_permission(self, request, view):
        """Checks if the api_key lives in the request."""
        if not request.user.is_authenticated:
            self.message = "Ops, you are not authenticated."
            return False

        if request.method != "POST":
            self.message = "Methods allowed ~> POST"
            return False

        if request.POST.get("api_key") is None:
            msg = "Hmm, did you forget to set your api_key in the request?"
            self.message = msg
            return False

        if request.POST["api_key"] != request.user.api_key:
            self.message = "Ouch, your api_key is not valid."
            return False

        return True


class GETSystemsCheck(permissions.BasePermission):
    """Sanity check for Systems type parameters."""

    message = "Invalid parameters."

    def has_permission(self, request, view):
        """Sanity checks for some api get methods that require system"""

        if request.method != "GET":
            self.message = "Methods allowed ~> GET"
            return False

        if request.GET.get("system", None) is None:
            self.message = "missing system type"
            return False

        if not request.GET.get("system").lower() in SYSTEMS:
            self.message = SYSTEMS_DROP
            return False

        return True


class UserCanScan(permissions.BasePermission):
    """Sanity check and see if the user has permission to do stuff."""

    def has_object_permission(self, request, view, obj):
        pass
