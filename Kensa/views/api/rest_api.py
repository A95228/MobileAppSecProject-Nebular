# -*- coding: utf_8 -*-
"""Kensa REST API V 1."""
import logging
import os
import re
# from rest_framework.pagination import PageNumberPagination
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from shelljob import proc
import shutil

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from Kensa.utils import api_key
from Kensa.views.helpers import request_method
from Kensa.views.home import RecentScans, Upload, delete_scan

from StaticAnalyzer.views.android import view_source
from StaticAnalyzer.views.android.static_analyzer import static_analyzer, get_app_name, valid_android_zip
from StaticAnalyzer.views.ios import view_source as ios_view_source
from StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios
from StaticAnalyzer.views.shared_func import pdf, score
from StaticAnalyzer.views.windows import windows
from StaticAnalyzer.models import StaticAnalyzerAndroid, StaticAnalyzerIOS
from django.contrib.auth.decorators import permission_required

from django.conf import settings
from Kensa.utils import (file_size)
from StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry)
from StaticAnalyzer.views.android.manifest_analysis import (get_manifest, manifest_data)

from StaticAnalyzer.views.shared_func import (hash_gen, unzip)

BAD_REQUEST = 400
FORBIDDEN = 403
OK = 200
INTERNAL_SERVER_ERR = 500

logger = logging.getLogger(__name__)


def make_api_response(data, status=OK):
    """Make API Response."""
    resp = JsonResponse(data=data, status=status)
    resp['Access-Control-Allow-Origin'] = '*'
    resp['Access-Control-Allow-Methods'] = 'POST'
    resp['Access-Control-Allow-Headers'] = 'Authorization'
    resp['Content-Type'] = 'application/json; charset=utf-8'
    return resp


def api_auth(meta):
    """Check if API Key Matches."""
    if 'HTTP_AUTHORIZATION' in meta:
        return bool(api_key() == meta['HTTP_AUTHORIZATION'])
    return False


def api_user_permission(request_user, md5, system):
    org_id = user = None
    if system == 'android':
        org_id, user = StaticAnalyzerAndroid.get_org_user(md5)
    elif system == 'ios':
        org_id, user = StaticAnalyzerIOS.get_org_user(md5)
    if org_id == '1':
        return True
    if request_user != user or user.organization != org_id:
        return False
    return True

@request_method(['POST'])
@csrf_exempt
def api_upload(request):
    """POST - Upload API."""
    upload = Upload(request)
    resp, code = upload.upload_api()
    return make_api_response(resp, code)


@request_method(['GET'])
@csrf_exempt
def api_recent_scans(request):
    """GET - get recent scans."""
    scans = RecentScans(request)
    resp = scans.recent_scans()
    if 'error' in resp:
        return make_api_response(resp, 500)
    else:
        return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_scan(request):
    """POST - Scan API."""
    params = ['scan_type', 'hash', 'file_name']
    if set(request.POST) >= set(params):
        scan_type = request.POST['scan_type']
        # APK, Android ZIP and iOS ZIP
        if scan_type in ['apk', 'zip']:
            resp = static_analyzer(request, True)
            if 'type' in resp:
                # For now it's only ios_zip
                request.POST._mutable = True
                request.POST['scan_type'] = 'ios'
                resp = static_analyzer_ios(request, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
        # IPA
        elif scan_type == 'ipa':
            resp = static_analyzer_ios(request, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
        # APPX
        elif scan_type == 'appx':
            resp = windows.staticanalyzer_windows(request, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_delete_scan(request):
    """POST - Delete a Scan."""
    if 'hash' in request.POST:
        resp = delete_scan(request, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_pdf_report(request):
    """Generate and Download PDF."""
    params = ['hash']
    if set(request.POST) == set(params):
        resp = pdf(request, api=True)
        if 'error' in resp:
            if resp.get('error') == 'Invalid scan hash':
                response = make_api_response(resp, 400)
            else:
                response = make_api_response(resp, 500)
        elif 'pdf_dat' in resp:
            response = HttpResponse(
                resp['pdf_dat'], content_type='application/pdf')
            response['Access-Control-Allow-Origin'] = '*'
        elif resp.get('report') == 'Report not Found':
            response = make_api_response(resp, 404)
        else:
            response = make_api_response(
                {'error': 'PDF Generation Error'}, 500)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_json_report(request):
    """Generate JSON Report."""
    params = ['hash']
    if set(request.POST) == set(params):
        resp = pdf(request, api=True, jsonres=True)
        if 'error' in resp:
            if resp.get('error') == 'Invalid scan hash':
                response = make_api_response(resp, 400)
            else:
                response = make_api_response(resp, 500)
        elif 'report_dat' in resp:
            response = make_api_response(resp['report_dat'], 200)
        elif resp.get('report') == 'Report not Found':
            response = make_api_response(resp, 404)
        else:
            response = make_api_response(
                {'error': 'JSON Generation Error'}, 500)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_view_source(request):
    """View Source for android & ios source file."""
    params = ['file', 'type', 'hash']
    if set(request.POST) >= set(params):
        if request.POST['type'] in ['eclipse', 'studio', 'apk']:
            resp = view_source.run(request, api=True)
        else:
            resp = ios_view_source.run(request, api=True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    else:
        response = make_api_response({'error': 'Missing Parameters'}, 422)
    return response


def make_app_info_response(app_dic, man_data_dic):
    resp_dic = {
        'file_name': app_dic['app_name'],
        'size': app_dic['size'],
        'md5': app_dic['md5'],
        'sha1': app_dic['sha1'],
        'sha256': app_dic['sha256'],
        'app_name': app_dic['real_name'],
        'package_name': man_data_dic['packagename'],
        'main_activity': man_data_dic['main_activity'],
        'target_sdk': man_data_dic['target_sdk'],
        'max_sdk': man_data_dic['max_sdk'],
        'min_sdk': man_data_dic['min_sdk'],
        'version_name': man_data_dic['version_name'],
        'version_code': man_data_dic['version_code']
    }
    return resp_dic


@request_method(['GET'])
def api_app_info(request):
    """Do static analysis on an request and save to db."""
    try:

        system = request.GET['system']
        md5 = request.GET['hash']
        # Input validation
        match = re.match('^[0-9a-f]{32}$', md5)
        if not api_user_permission(request.user, md5, system):
            return make_api_response({'error': 'You have not proper permission'}, FORBIDDEN)
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


@request_method(['GET'])
def api_app_store(request):
    try:
        md5 = request.GET['hash']
        system = request.GET['system']
        match = re.match('^[0-9a-f]{32}$', md5)
        if match:
            app_store_info = {}
            if system == 'android':
                app_store_info = StaticAnalyzerAndroid.get_app_store(md5)
            elif system == 'ios':
                app_store_info = StaticAnalyzerIOS.get_app_store(md5)
            # else system == 'windows':
            #     app_info = StaticAnalyzerWindows.get_app_info(md5)
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


@request_method(['GET'])
def api_code_smali(request):
    # try:
    #     page = request.GET.get('page', 0)
    #     md5 = request.GET['md5']
    #     match = re.match('^[0-9a-f]{32}$', request.GET['md5'])
    #     if not match:
    #         return make_api_response({'error': 'Scan hash not found'}, OK)
    #     src = os.path.join(settings.UPLD_DIR, md5 + '/smali_source/')
    #     smali_files = []
    #     for dir_name, _sub_dir, files in os.walk(src):
    #         for jfile in files:
    #             if jfile.endswith('.smali'):
    #                 file_path = os.path.join(src, dir_name, jfile)
    #                 if '+' in jfile:
    #                     fp2 = os.path.join(
    #                         src, dir_name, jfile.replace('+', 'x'))
    #                     shutil.move(file_path, fp2)
    #                     file_path = fp2
    #                 fileparam = file_path.replace(src, '')
    #                 smali_files.append(escape(fileparam))
    #     context = {
    #         'title': 'Smali Source',
    #         'files': smali_files,
    #         'type': 'apk',
    #         'hash': md5,
    #         'version': settings.KENSA_VER,
    #     }
    #     return render(request, template, context)
    # except Exception as excep:
    #     logger.exception('Error calling api_malware_overview')
    #     msg = str(excep)
    #     exp = excep.__doc__
    #     return make_api_response({'error': msg}, BAD_REQUEST)
    pass


@request_method(['GET'])
def api_security_overview(request):
    try:
        md5 = request.GET['hash']
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


@request_method(['GET'])
def api_malware_overview(request):
    try:
        md5 = request.GET['hash']
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


def create_pagination_response(context, page):
    paginator = Paginator(context, 30)
    try:
        activities = paginator.page(page)
    except PageNotAnInteger:
        activities = paginator.page(1)
    except EmptyPage:
        activities = paginator.page(paginator.num_pages)

    resp = {
        'page': activities.number,
        'limit': 30,
        'list': activities.object_list
    }
    return resp


@request_method(['GET'])
def api_components_activities(request):
    try:
        md5 = request.GET['hash']
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


@request_method(['GET'])
def api_components_services(request):
    try:
        md5 = request.GET['hash']
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


@request_method(['GET'])
def api_components_receivers(request):
    try:
        md5 = request.GET['hash']
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


@request_method(['GET'])
def api_components_providers(request):
    try:
        md5 = request.GET['hash']
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


@request_method(['GET'])
def api_components_libraries(request):
    try:
        md5 = request.GET['hash']
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


@request_method(['GET'])
def api_components_files(request):
    try:
        md5 = request.GET['hash']
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


@request_method(['GET'])
def api_domain_analysis(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        system = request.GET['system']
        if match:
            domains = {}
            if system == 'android':
                domains = StaticAnalyzerAndroid.get_domain_analysis(md5)
            # elif system == 'ios':
            #     domains = StaticAnalyzerIOS.get_malware_overview(md5)
            #
            # db_entry = StaticAnalyzerAndroid.objects.filter(
            #     MD5=md5)
            # if db_entry.exists():
            #     context = get_context_from_db_entry(db_entry)
            #     if context['domains']:
            #         return make_api_response(context['domains'], OK)
            return make_api_response({'msg': 'Not exist'}, OK)
        else:
            return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error calling api_domain_analysis')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)


@request_method(['GET'])
def api_manifest_analysis(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        system = request.GET['system']
        if system != 'android':
            return make_api_response({'error': 'This API only supports for Android'}, OK)
        if match:
            manifest = StaticAnalyzerAndroid.get_manifest_analysis(md5)
            if match is not None:
                return make_api_response({'count': len(manifest), 'list': manifest}. OK)
            return make_api_response({'msg': 'Not exist'}, OK)
        else:
            return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error calling api_manifest_analysis')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)


@request_method(['GET'])
def api_code_analysis(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        system = request.GET['system']
        if match:
            code_analysis = {}
            if system == 'android':
                code_analysis = StaticAnalyzerAndroid.get_code_analysis(md5)
            elif system == 'ios':
                code_analysis = StaticAnalyzerIOS.get_code_analysis(md5)
            if code_analysis is not None:
                return make_api_response(code_analysis, OK)
            return make_api_response({'msg': 'Not exist'}, OK)
        else:
            return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error calling api_code_analysis')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)


@request_method(['GET'])
def api_file_analysis(request):
    try:
        md5 = request.GET['hash']
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


@request_method(['GET'])
def api_app_permissions(request):
    try:
        md5 = request.GET['hash']
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


@request_method(['GET'])
def api_binary_analysis(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        system = request.GET['system']
        if match:
            binary_analysis = []
            if system == 'android':
                binary_analysis = StaticAnalyzerAndroid.get_binary_analysis(md5)
            elif system == 'ios':
                binary_analysis = StaticAnalyzerIOS.get_binary_analysis(md5)
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

