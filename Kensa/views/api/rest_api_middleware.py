# -*- coding: utf_8 -*-
"""REST API Middleware."""
import re

from django.utils.deprecation import MiddlewareMixin
from Kensa.views.api.views import make_api_response, api_auth, api_user_permission


class RestApiAuthMiddleware(MiddlewareMixin):
    """
    Middleware.

    Middleware for REST API.
    """
    def process_request(self, request):
        """Middleware to handle API Auth."""
        if not request.path.startswith('/api/'):
            return

        if request.method == 'OPTIONS':
            return make_api_response({}, 200)
        
        #if not api_auth(request.META):
        #   return make_api_response(
        #       {'error': 'You are unauthorized to make this request.'}, 401)
        #if not api_user_permission(request):
        #   return make_api_response({'error': 'You are unauthorized to make this request.'}, 403)


