# -*- coding: utf_8 -*-
"""Kensa REST API V 1."""
import logging
import os
from shelljob import proc

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from Kensa.utils import api_key
from Kensa.views.helpers import request_method
from Kensa.views.home import RecentScans, Upload, delete_scan

from StaticAnalyzer.views.android import view_source
from StaticAnalyzer.views.android.static_analyzer import static_analyzer
from StaticAnalyzer.views.ios import view_source as ios_view_source
from StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios
from StaticAnalyzer.views.shared_func import pdf
from StaticAnalyzer.views.windows import windows
from StaticAnalyzer.models import StaticAnalyzerAndroid
from django.contrib.auth.decorators import permission_required

from django.conf import settings
from Kensa.utils import (get_device,
                         get_proxy_ip,
                         print_n_send_error_response)

from DynamicAnalyzer.views.android.environment import Environment
from DynamicAnalyzer.views.android.operations import (
    is_attack_pattern,
    is_md5,
    strict_package_check)
from DynamicAnalyzer.tools.webproxy import (
    start_httptools_ui,
    stop_httptools)


BAD_REQUEST = 400
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


@request_method(['GET'])
@csrf_exempt
@permission_required
def dynamic_analysis(request):
    """Android Dynamic Analysis Entry point."""
    try:
        apks = StaticAnalyzerAndroid.objects.filter(
            APP_TYPE='apk').order_by('-id')
        try:
            identifier = get_device()
        except Exception:
            msg = ('Is Andoird VM running? Kensa cannot'
                   ' find android instance identifier.'
                   ' Please run an android instance and refresh'
                   ' this page. If this error persists,'
                   ' set ANALYZER_IDENTIFIER in Kensa/settings.py')
            err_response = print_n_send_error_response(request, msg, api=True)
            response = make_api_response(err_response, INTERNAL_SERVER_ERR)
            return response

        proxy_ip = get_proxy_ip(identifier)
        context = {'apks': apks,
                   'identifier': identifier,
                   'proxy_ip': proxy_ip,
                   'proxy_port': settings.PROXY_PORT,
                   'title': 'Kensa Dynamic Analysis',
                   'version': settings.KENSA_VER}
        response = make_api_response(context, OK)
        return response
    except Exception as exp:
        logger.exception('Dynamic Analysis')
        err_response = print_n_send_error_response(request, exp)
        return make_api_response(err_response, INTERNAL_SERVER_ERR)


@request_method(['GET'])
@csrf_exempt
@permission_required
def dynamic_analyzer(request):
    """Android Dynamic Analyzer Environment."""
    try:
        bin_hash = request.GET['hash']
        package = request.GET['package']
        no_device = False
        if (is_attack_pattern(package) or not
                is_md5(bin_hash)):
            error_response = print_n_send_error_response(request, 'Invalid Parameters', api=True)
            return make_api_response(error_response, INTERNAL_SERVER_ERR)

        identifier = ''
        try:
            identifier = get_device()
        except Exception:
            no_device = True
        if no_device or not identifier:
            msg = ('Is the android instance running? Kensa cannot'
                   ' find android instance identifier. '
                   'Please run an android instance and refresh'
                   ' this page. If this error persists,'
                   ' set ANALYZER_IDENTIFIER in Kensa/settings.py')
            err_response = print_n_send_error_response(request, msg, api=True)
            return make_api_response(err_response, INTERNAL_SERVER_ERR)
        env = Environment(identifier)
        if not env.connect_n_mount():
            msg = 'Cannot Connect to ' + identifier
            err_response = print_n_send_error_response(request, msg, api=True)
            return make_api_response(err_response, INTERNAL_SERVER_ERR)

        version = env.get_android_version()

        logger.info('Android Version identified as %s', version)

        xposed_first_run = False
        if not env.is_kensayied(version):
            msg = ('This Android instance is not Kensayed.\n'
                   'Kensaying the android runtime environment')
            logger.warning(msg)
            if not env.kensay_init():
                err_response = print_n_send_error_response(
                    request,
                    'Failed to Kensay the instance', api=True)
                return make_api_response(err_response, INTERNAL_SERVER_ERR)
            if version < 5:
                xposed_first_run = True
        if xposed_first_run:
            msg = ('Have you Kensayed the instance before'
                   ' attempting Dynamic Analysis?'
                   ' Install Framework for Xposed.'
                   ' Restart the device and enable'
                   ' all Xposed modules. And finally'
                   ' restart the device once again.')
            err_response = print_n_send_error_response(request, msg, api=True)
            return make_api_response(err_response, INTERNAL_SERVER_ERR)
        # Clean up previous analysis
        env.dz_cleanup(bin_hash)
        # Configure Web Proxy
        env.configure_proxy(package)
        # Supported in Android 5+
        env.enable_adb_reverse_tcp(version)
        # Apply Global Proxy to device
        env.set_global_proxy(version)
        # Start Clipboard monitor
        env.start_clipmon()
        # Get Screen Resolution
        screen_width, screen_height = env.get_screen_res()
        logger.info('Installing APK')
        app_dir = os.path.join(settings.UPLD_DIR,
                               bin_hash + '/')  # APP DIRECTORY
        apk_path = app_dir + bin_hash + '.apk'  # APP PATH
        env.adb_command(['install', '-r', apk_path], False, True)
        logger.info('Testing Environment is Ready!')
        context = {'screen_witdth': screen_width,
                   'screen_height': screen_height,
                   'package': package,
                   'md5': bin_hash,
                   'android_version': version,
                   'version': settings.KENSA_VER,
                   'title': 'Dynamic Analyzer'}
        template = 'dynamic_analysis/android/dynamic_analyzer.html'
        return make_api_response(context, OK)
    except Exception:
        logger.exception('Dynamic Analyzer')
        err_response = print_n_send_error_response(request, 'Dynamic Analysis Failed.', True)
        return make_api_response(err_response, INTERNAL_SERVER_ERR)


@request_method(['GET'])
@csrf_exempt
def httptools_start(request):
    """Start httprools UI."""
    logger.info('Starting httptools Web UI')
    try:
        stop_httptools(settings.PROXY_PORT)
        start_httptools_ui(settings.PROXY_PORT)
        logger.info('httptools UI started')
        if request.GET['project']:
            project = request.GET['project']
        else:
            project = ''
        url = ('http://localhost:{}'
               '/dashboard/{}'.format(
                   str(settings.PROXY_PORT),
                   project))
        response = {'project_url': url}
        return make_api_response(response, OK)
    except Exception:
        logger.exception('Starting httptools Web UI')
        err = 'Error Starting httptools UI'
        err_response = print_n_send_error_response(request, err, api=True)
        return make_api_response(err_response, INTERNAL_SERVER_ERR)

# def logcat(request):
#     logger.info('Starting Logcat streaming')
#     try:
#         pkg = request.GET.get('package')
#         if pkg:
#             if not strict_package_check(pkg):
#                 err_response = print_n_send_error_response(
#                     request, 'Invalid package name', api=True)
#                 return make_api_response(err_response, INTERNAL_SERVER_ERR)
#             ok_response = {'package': pkg}
#             return make_api_response(ok_response, OK)
#         app_pkg = request.GET.get('app_package')
#         if app_pkg:
#             if not strict_package_check(app_pkg):
#                 err_response = print_n_send_error_response(
#                     request, 'Invalid package name', api=True)
#             adb = os.environ['KENSA_ADB']
#             g = proc.Group()
#             g.run([adb, 'logcat', app_pkg + ':V', '*:*'])
#
#             def read_process():
#                 while g.is_pending():
#                     lines = g.readlines()
#                     for _, line in lines:
#                         time.sleep(.01)
#                         yield 'data:{}\n\n'.format(line)
#             return StreamingHttpResponse(read_process(),
#                                          content_type='text/event-stream')
#         return print_n_send_error_response(
#             request,
#             'Invalid parameters')
#     except Exception:
#         logger.exception('Logcat Streaming')
#         err = 'Error in Logcat streaming'
#         return print_n_send_error_response(request, err)