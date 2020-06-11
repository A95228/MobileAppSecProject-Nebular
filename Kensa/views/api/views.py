from Kensa.views.api.rest_api import make_api_response
from StaticAnalyzer.models import(
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS
)

from rest_framework.generics import RetrieveAPIView
from rest_framework.permissions import IsAuthenticated

import logging
import re

logger = logging.getLogger(__name__)


BAD_REQUEST = 400
OK = 200
NOT_FOUND = 404
FORBIDDEN = 403
INTERNAL_SERVER_ERR = 500


class AppInfoView(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            system = request.GET['system']
            md5 = request.GET['md5']
            # Input validation
            match = re.match('^[0-9a-f]{32}$', md5)
            # if not api_user_permission(request.user, md5, system):
            #     return make_api_response({'error': 'You have not proper permission'}, FORBIDDEN)
            if match:
                app_info = {}
                if system == 'android':
                    app_info = StaticAnalyzerAndroid.get_app_info(md5)
                elif system == 'ios':
                    app_info = StaticAnalyzerIOS.get_app_info(md5)
                # else system == 'windows':
                #     app_info = StaticAnalyzerWindows.get_app_info(md5)
                else:
                    return make_api_response({'error': 'SYSTEM type error'}, BAD_REQUEST)
                if app_info is not None:
                    return make_api_response(app_info, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH err'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error Performing Static Analysis')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)
