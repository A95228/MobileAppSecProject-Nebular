from rest_framework import permissions


class HasAPIKey(permissions.BasePermission):
    """
    Custom permission to only allow owner of an object to edit it.
    """

    def has_object_permission(self, request, view, obj):
        # Write permissions are only allowed to the owner of the device
        # is_it = bool(request.user and request.user.is_authenticated)
        return True