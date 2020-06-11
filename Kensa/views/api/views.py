from Kensa.views.api.rest_api import make_api_response, create_pagination_response
from StaticAnalyzer.models import(
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS
)

from rest_framework.generics import RetrieveAPIView
from rest_framework.permissions import IsAuthenticated

import logging
import re

from StaticAnalyzer.views.shared_func import score

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


class AppStoreView(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            system = request.GET['system']
            match = re.match('^[0-9a-f]{32}$', md5)
            if match:
                app_store_info = {}
                if system == 'android':
                    app_store_info = StaticAnalyzerAndroid.get_app_store(md5)
                elif system == 'ios':
                    app_store_info = StaticAnalyzerIOS.get_app_store(md5)
                else:
                    return make_api_response({'error': 'SYSTEM type error'}, BAD_REQUEST)
                return make_api_response(app_store_info, OK)
            else:
                return make_api_response({'error': 'HASH err'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_app_store')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class SecurityOverView(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            match = re.match('^[0-9a-f]{32}$', md5)
            system = request.GET['system']
            if match:
                security_overview = {}
                if system == 'android':
                    security_overview = StaticAnalyzerAndroid.get_security_overview(md5)
                elif system == 'ios':
                    security_overview = StaticAnalyzerIOS.get_security_overview(md5)
                if security_overview is not None:
                    return make_api_response(security_overview, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_security_overview')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class MalwareOverView(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            match = re.match('^[0-9a-f]{32}$', md5)
            system = request.GET['system']
            if match:
                malware_overview = {}
                if system == 'android':
                    _, malware_overview = score(StaticAnalyzerAndroid.get_code_analysis(md5))
                elif system == 'ios':
                    _, malware_overview = score(StaticAnalyzerIOS.get_code_analysis(md5))
                # elif system == 'windows':
                #     malware_overview = StaticAnalyzerWindows.get_malware_overview(md5)

                if malware_overview is not None:
                    return make_api_response({'security_score': malware_overview}, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_malware_overview')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class ComponentsActivities(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            page = int(request.GET.get('page', 1))
            system = request.GET['system']
            match = re.match('^[0-9a-f]{32}$', md5)
            if system != 'android':
                return make_api_response({'error': 'This API only supports for Android'}, BAD_REQUEST)
            if match:
                activities = StaticAnalyzerAndroid.get_components_activities(md5)
                if activities is not None:
                    resp = create_pagination_response(activities, page)
                    return make_api_response(resp, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_malware_overview')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class ComponentsServices(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            page = int(request.GET.get('page', 1))
            match = re.match('^[0-9a-f]{32}$', md5)
            system = request.GET['system']
            if system != 'android':
                return make_api_response({'error': 'This API only supports for Android'}, BAD_REQUEST)
            if match:
                services = StaticAnalyzerAndroid.get_components_services(md5)
                if services is not None:
                    resp = create_pagination_response(services, page)
                    return make_api_response(resp, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_malware_overview')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class ComponentsReceivers(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            page = int(request.GET.get('page', 1))
            match = re.match('^[0-9a-f]{32}$', md5)
            system = request.GET['system']
            if system != 'android':
                return make_api_response({'error': 'This API only supports for Android'}, BAD_REQUEST)
            if match:
                receivers = StaticAnalyzerAndroid.get_components_services(md5)
                if receivers is not None:
                    resp = create_pagination_response(receivers, page)
                    return make_api_response(resp, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_malware_overview')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class ComponentsProviders(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            page = int(request.GET.get('page', 1))
            match = re.match('^[0-9a-f]{32}$', md5)
            system = request.GET['system']
            if system != 'android':
                return make_api_response({'error': 'This API only supports for Android'}, BAD_REQUEST)
            if match:
                providers = StaticAnalyzerAndroid.get_components_providers(md5)
                if providers is not None:
                    resp = create_pagination_response(providers, page)
                    return make_api_response(resp, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_malware_overview')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class ComponentsLibraries(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            page = int(request.GET.get('page', 1))
            match = re.match('^[0-9a-f]{32}$', md5)
            system = request.GET['system']

            if match:
                libraries = []
                if system == 'android':
                    libraries = StaticAnalyzerAndroid.get_components_libraries(md5)
                elif system == 'ios':
                    libraries = StaticAnalyzerIOS.get_components_libraries(md5)

                if libraries is not None:
                    resp = create_pagination_response(libraries, page)
                    return make_api_response(resp, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_malware_overview')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class ComponentsFiles(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            page = int(request.GET.get('page', 1))
            match = re.match('^[0-9a-f]{32}$', md5)
            system = request.GET['system']
            if match:
                files = []
                if system == 'android':
                    files = StaticAnalyzerAndroid.get_components_files(md5)
                elif system == 'ios':
                    files = StaticAnalyzerIOS.get_components_files(md5)
                if files is not None:
                    resp = create_pagination_response(files, page)
                    return make_api_response(resp, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_malware_overview')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class DomainAnalysis(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            match = re.match('^[0-9a-f]{32}$', md5)
            system = request.GET['system']
            if match:
                domains = {}
                if system == 'android':
                    domains = StaticAnalyzerAndroid.get_domain_analysis(md5)
                # elif system == 'ios':
                #     domains = StaticAnalyzerIOS.get_malware_overview(md5)
                    return make_api_response(domains, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_domain_analysis')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class APKIDAnalysis(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            match = re.match('^[0-9a-f]{32}$', md5)
            if match:
                apkid = StaticAnalyzerAndroid.get_apkid_analysis(md5)
                return make_api_response(apkid, OK)
        except Exception as excep:
            logger.exception('Error calling api_domain_analysis')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class ManifestAnalysis(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            match = re.match('^[0-9a-f]{32}$', md5)
            page = request.GET['page']

            if match:
                manifest = StaticAnalyzerAndroid.get_manifest_analysis(md5)
                resp = create_pagination_response(manifest['list'], page)
                if match is not None:
                    return make_api_response({'total_count': manifest['count'], 'pageinfo': resp}, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_manifest_analysis')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class CodeAnalysis(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            match = re.match('^[0-9a-f]{32}$', md5)
            system = request.GET['system']
            if match:
                code_analysis = {}
                if system == 'android':
                    code_analysis = StaticAnalyzerAndroid.get_code_analysis_report(md5)
                elif system == 'ios':
                    code_analysis = StaticAnalyzerIOS.get_code_analysis_report(md5)
                if code_analysis is not None:
                    return make_api_response({'count': len(code_analysis), 'list': code_analysis}, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_code_analysis')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class FileAnalysis(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            match = re.match('^[0-9a-f]{32}$', md5)
            system = request.GET['system']
            if match:
                file_analysis = []
                if system == 'android':
                    file_analysis = StaticAnalyzerAndroid.get_file_analysis(md5)
                elif system == 'ios':
                    file_analysis = StaticAnalyzerIOS.get_file_analysis(md5)
                if file_analysis is not None:
                    return make_api_response({'count': len(file_analysis), 'list': file_analysis}, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_file_analysis')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class AppPermissions(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            match = re.match('^[0-9a-f]{32}$', md5)
            system = request.GET['system']
            if match:
                app_permissions = []
                if system == 'android':
                    app_permissions = StaticAnalyzerAndroid.get_app_permissions(md5)
                elif system == 'ios':
                    app_permissions = StaticAnalyzerIOS.get_app_permissions(md5)
                if app_permissions is not None:
                    return make_api_response({'count': len(app_permissions), 'list': app_permissions}, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_binary_analysis')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)


class BinaryAnalysis(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            md5 = request.GET['md5']
            match = re.match('^[0-9a-f]{32}$', md5)
            system = request.GET['system']
            if match:
                binary_analysis = []
                # if system == 'android':
                binary_analysis = StaticAnalyzerAndroid.get_binary_analysis(md5)
                # elif system == 'ios':
                #     binary_analysis = StaticAnalyzerIOS.get_binary_analysis(md5)
                if binary_analysis is not None:
                    return make_api_response({'count': len(binary_analysis), 'list': binary_analysis}, OK)
                return make_api_response({'msg': 'Not exist'}, OK)
            else:
                return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
        except Exception as excep:
            logger.exception('Error calling api_binary_analysis')
            msg = str(excep)
            exp = excep.__doc__
            return make_api_response({'error': msg}, BAD_REQUEST)
