# -*- coding: utf_8 -*-
"""Kensa REST API V 1."""
import logging
import re
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from Kensa.utils import api_key
from Kensa.views.helpers import request_method
from Kensa.views.home import RecentScans, Upload, delete_scan

from StaticAnalyzer.views.android import view_source
from StaticAnalyzer.views.android.static_analyzer import static_analyzer
from StaticAnalyzer.views.ios import view_source as ios_view_source
from StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios
from StaticAnalyzer.views.shared_func import pdf, score
from StaticAnalyzer.views.windows import windows

from StaticAnalyzer.models import(
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS
)

from StaticAnalyzer.views.android.java import api_run_java_code
from StaticAnalyzer.views.android.smali import api_run_smali


BAD_REQUEST = 400
FORBIDDEN = 403
OK = 200
INTERNAL_SERVER_ERR = 500
NOT_FOUND = 404
SYSTEMS = [
    "ios",
    "android"
]

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


def api_user_permission(request):
    try:
        if request.path.startswith('api/v1/upload') or request.path.startswith('api/v1/scan'):
            return True
        request_user = request.user
        system = request.GET['system']
        md5 = request.GET['md5']
        org_id = user = None
        if system == 'android':
            org_id, user = StaticAnalyzerAndroid.get_org_user(md5)
        elif system == 'ios':
            org_id, user = StaticAnalyzerIOS.get_org_user(md5)
        if org_id == '1' or request_user.id == 1:
            return True
        if request_user != user or user.organization != org_id:
            return False
        return True
    except:
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


@request_method(['GET'])
def api_app_store(request):
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


@request_method(["GET"])
def api_get_search(request):
    """Get search results"""
    if request.GET.get("md5",None) is None:
        return make_api_response({"error" : "Missing Identifier"}, 
            status=BAD_REQUEST)
    if not re.match(r"^[0-9a-f]{1,32}$", request.GET["md5"]):
        return make_api_response({"error" : "Invalid identifier"}, 
            status=BAD_REQUEST)
    md5 = request.GET["md5"]
    ios_md5s = StaticAnalyzerIOS.get_md5s(md5)
    android_md5s = StaticAnalyzerAndroid.get_md5s(md5)
    search_results = tools.merge_searches(ios_md5s, android_md5s)
    if not len(search_results) > 0:
        return make_api_response({"error" : "0 search results for %s." % md5},
            status=NOT_FOUND)
    return make_api_response({"results" : search_results}, status=OK)


@request_method(["GET"])
def api_get_recent_scans(request):
    """Get Recent Scans """
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    data = RecentScansDB.get_recent_scans()
    if data is not None:
        if isinstance(data, dict):
            return make_api_response(data=data, status=OK)
        return JsonResponse(data=data, safe=False, status=OK) # strange case
    return make_api_response(data={"error" : "no data"}, status=BAD_REQUEST)


@request_method(["GET"])
def api_get_signer_certificate(request):
    """Get certificate"""
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    if request.GET.get("md5", None) is None:
        return make_api_response(data={"error" : "missing md5"}, 
            status=BAD_REQUEST)
    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return make_api_response(data={"error" : "invalid identifier"}, 
            status=BAD_REQUEST)
    try:
        data = StaticAnalyzerAndroid.get_certificate_analysis_data(
            request.GET["md5"])
    except:
        return make_api_response({"error" : "contact sysadmin"},
            status=500)
    if data is None:
        return make_api_response(data={"info" : "nothing found"}, 
            status=NOT_FOUND)
    return make_api_response(data=data, status=OK)
    

@request_method(["GET"])
def api_get_manifest(request):
    """Get manifest"""
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    if request.GET.get("md5", None) is None:
        return make_api_response(data={"error" : "missing md5"}, 
            status=BAD_REQUEST)
    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return make_api_response(data={"error" : "invalid identifier"}, 
            status=NOT_FOUND)
    try:
        data = StaticAnalyzerAndroid.get_manifest(request.GET["md5"])
    except:
        return make_api_response({"error" : "contact sysadmin"},
            status=500)
    if data is None:
        return make_api_response(data={"info" : "no data to preview"})
    return JsonResponse(data=data, status=OK)


@request_method(["GET"])
def api_get_domains_data(request):
    """Get domains data"""
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "missing identifier"}, 
            status=BAD_REQUEST)
    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return make_api_response({"error" : "invalid identifier"}, 
            status=BAD_REQUEST)
    try:
        data = StaticAnalyzerAndroid.get_domains_data(
            request.GET["md5"])
    except:
        return make_api_response({"error" : "contact sysadmin"},
            status=500)
    if data is None:
        return make_api_response({"error": "No data to preview"}, 
            status=NOT_FOUND)
    return make_api_response(data=data, status=OK)


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# API JAVA & SMALI ROUTES
# Both routes are paginated.
#   Examples:
#       /api/v1/code/java?md5=<md5>&type=<apk>&page=<page_num> 
#       /api/v1/code/smali?md5=<md5>&page=<page_num>
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


@request_method(["GET"])
def api_get_java_code(request):
    """Get a list of java code files"""
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "missing identifier"}, 
            status=BAD_REQUEST)
    if request.GET.get("type", None) is None:
        return make_api_response({"error" : "missing type"}, 
            status=BAD_REQUEST)
    if request.GET.get("page", None) is not None:
        if re.match(r"^\d+$", request.GET["page"]):
            page = request.GET["page"]
        else:
            page = 1
    else:
        page = 1
    try:
        ctx = api_run_java_code(request)
    except:
        return make_api_response({"error" : "contact sysadmin"},
            status=500)
    if 'error' in ctx:
        return make_api_response(data=ctx, status=BAD_REQUEST)
    # inject pagination
    try:
        files = StaticAnalyzerAndroid.paginate(ctx["files"], page)
    except:
        pass
    else:
        ctx.update({"files" : files})
    return make_api_response(data=ctx, status=OK)


@request_method(["GET"])
def api_get_smali_code(request):
    """Get smali code"""
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "missing identifier"}, 
            status=BAD_REQUEST)
    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return make_api_response({"error" : "invalid identifier"}, 
            status=BAD_REQUEST)
    if request.GET.get("page", None) is not None:
        if re.match(r"^\d+$", request.GET["page"]):
            page = request.GET["page"]
        else:
            page = 1
    else:
        page = 1
    try:
        ctx = api_run_smali(request)
    except RecursionError as run_error:
        return make_api_response({"error" : "contact sysadmin"},
            status=500)
    except Exception as error:
        logger.error(str(error))
        return make_api_response({"error" : "contact sysadmin"},
            status=500)
    if 'error' in ctx:
        return make_api_response(ctx, 500)
    elif 'files' in ctx:
        pass
    if ctx["files"].__len__() == 0:
        return make_api_response(
            {"error" : "no smali files for %s" % request.GET["md5"]}, 500)
    # inject pagination
    try:
        files = StaticAnalyzerAndroid.paginate(ctx["files"], page)
    except:
        pass
    else:
        ctx.update({"files" : files})

    return make_api_response(data=ctx, status=OK)


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# API RECONNAISSANCE ROUTES
# Routes are paginated.
#
#   Examples for routes that are for Android and IOS
#   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#       /api/v1/recon_emails?md5=<md5>&system=<ios|android>page=<page_num>
#       /api/v1/recon_firebase?md5=<md5>&system=<ios|android>page=<page_num>
#       /api/v1/recon_urls?md5=<md5>&system=<ios|android>page=<page_num>
#       /api/v1/recon_strings?md5=<md5>&system=<ios|android>page=<page_num> 
#
#   Examples for routes that are just for Android
#   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#       /api/v1/recon_trackers?md5=<md5>&page=<page_num>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


@request_method(["GET"])
def api_get_recon_emails(request):
    """Get reconnaissance emails or error"""
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "missing identifier"}, 
            status=BAD_REQUEST)
    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return make_api_response(
            {"error" : "Invalid identifier"}, 
            status=BAD_REQUEST)
    if request.GET.get("system", None) is None:
        return make_api_response({"error" : "missing system type"},
            status=BAD_REQUEST)
    if not request.GET.get("system").lower() in SYSTEMS:
        return make_api_response(
            {"error" : "Systems allowed: %s" % ", ".join(SYSTEMS)},
            status=BAD_REQUEST)
    if request.GET.get("page", None) is not None:
        if re.match(r"^\d+$", request.GET["page"]):
            page = request.GET["page"]
        else:
            page = 1
    else:
        page = 1
    system = request.GET.get("system")
    md5 = request.GET.get("md5")
    if system == "android":
        emails = StaticAnalyzerAndroid.get_recon_emails(md5, page)
    elif system == "ios":
        emails = StaticAnalyzerIOS.get_recon_emails(md5, page)
    if emails is None:
        return make_api_response({"error" : "no emails for %s" % md5}, 
            status=NOT_FOUND)
    return make_api_response(emails, status=OK)


@request_method(["GET"])
def api_get_recon_urls(request):
    """Get reconnaissance urls"""
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "missing identifier"}, 
            status=BAD_REQUEST)
    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return make_api_response(
            {"error" : "Invalid identifier"}, 
            status=BAD_REQUEST)
    if request.GET.get("system", None) is None:
        return make_api_response({"error" : "missing system type"},
            status=BAD_REQUEST)
    if not request.GET.get("system").lower() in SYSTEMS:
        return make_api_response(
            {"error" : "Systems allowed: %s" % ", ".join(SYSTEMS)},
            status=BAD_REQUEST)
    if request.GET.get("page", None) is not None:
        if re.match(r"^\d+$", request.GET["page"]):
            page = request.GET["page"]
        else:
            page = 1
    else:
        page = 1
    system = request.GET.get("system")
    md5 = request.GET.get("md5")
    if system == "android":
        urls = StaticAnalyzerAndroid.get_recon_urls(md5, page)
    elif system == "ios":
        urls = StaticAnalyzerIOS.get_recon_urls(md5, page)
    if urls is None:
        return make_api_response({"error" : "no urls for %s" % md5}, 
            status=NOT_FOUND)
    return make_api_response(urls, status=OK)


@request_method(["GET"])
def api_get_recon_firebase_db_urls(request):
    """Get recon firebase or error"""
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
            status=BAD_REQUEST)
    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return make_api_response({"error" : "Invalid identifier"},
            status=BAD_REQUEST)
    if request.GET.get("system", None) is None:
        return make_api_response({"error" : "missing system type"},
            status=BAD_REQUEST)
    if not request.GET.get("system").lower() in SYSTEMS:
        return make_api_response(
            {"error" : "Systems allowed: %s" % ", ".join(SYSTEMS)},
            status=BAD_REQUEST)
    if request.GET.get("page", None) is not None:
        if re.match(r"^\d+$", request.GET["page"]):
            page = request.GET["page"]
        else:
            page = 1
    else:
        page = 1
    system = request.GET.get("system")
    md5 = request.GET.get("md5")
    if system == "android":
        firebase_urls = StaticAnalyzerAndroid.get_recon_firebase_db(md5, page)
    elif system == "ios":
        firebase_urls = StaticAnalyzerIOS.get_recon_firebase_db(md5, page)
    if firebase_urls is None:
        return make_api_response({"error" : "no firebase urls for %s" % md5}, 
            status=NOT_FOUND)
    return make_api_response(firebase_urls, status=OK)


@request_method(["GET"])
def api_get_recon_strings(request):
    """Get recon strings or error"""
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
            status=BAD_REQUEST)
    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return make_api_response({"error" : "Invalid identifier"},
            status=BAD_REQUEST)
    if request.GET.get("system", None) is None:
        return make_api_response({"error" : "missing system type"},
            status=BAD_REQUEST)
    if not request.GET.get("system").lower() in SYSTEMS:
        return make_api_response(
            {"error" : "Systems allowed: %s" % ", ".join(SYSTEMS)},
            status=BAD_REQUEST)
    if request.GET.get("page", None) is not None:
        if re.match(r"^\d+$", request.GET["page"]):
            page = request.GET["page"]
        else:
            page = 1
    else:
        page = 1
    system = request.GET.get("system")
    md5 = request.GET.get("md5")
    if system == "android":
        strings = StaticAnalyzerAndroid.get_recon_strings(md5, page)
    elif system == "ios":
        strings = StaticAnalyzerIOS.get_recon_strings(md5, page)
    if strings is None:
        return make_api_response({"error" : "no strings for %s" % md5}, 
            status=NOT_FOUND)
    return make_api_response(strings, status=OK)


@request_method(["GET"])
def api_get_recon_trackers(request):
    """Get recon trackers or error"""
    #if not request.user.is_authenticated:
    #    return make_api_response({"error" : "login and try again"},
    #        status=401)
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
            status=BAD_REQUEST)
    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return make_api_response({"error" : "Invalid identifier"},
            status=BAD_REQUEST)
    if request.GET.get("page", None) is not None:
        if re.match(r"^\d+$", request.GET["page"]):
            page = request.GET["page"]
        else:
            page = 1
    else:
        page = 1
    md5 = request.GET["md5"]
    try:
        trackers = StaticAnalyzerAndroid.get_recon_trackers(md5, page)
    except:
        return make_api_response({"error" : "contact sysadmin"},
            status=500)
    if trackers is None:
        return make_api_response({"error" : "no trackers for %s" % md5}, 
            status=NOT_FOUND)
    return make_api_response(trackers, status=OK)
	


@request_method(['GET'])
def api_security_overview(request):
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


@request_method(['GET'])
def api_malware_overview(request):
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


@request_method(['GET'])
def api_components_services(request):
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


@request_method(['GET'])
def api_components_receivers(request):
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


@request_method(['GET'])
def api_components_providers(request):
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


@request_method(['GET'])
def api_components_libraries(request):
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


@request_method(['GET'])
def api_components_files(request):
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


@request_method(['GET'])
def api_domain_analysis(request):
    try:
        md5 = request.GET['md5']
        match = re.match('^[0-9a-f]{32}$', md5)
        system = request.GET['system']
        if match:
            domains = {}
            if system == 'android':
                domains = StaticAnalyzerAndroid.get_domain_analysis(md5)
            elif system == 'ios':
                domains = StaticAnalyzerIOS.get_domain_analysis(md5)
                return make_api_response(domains, OK)
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
        md5 = request.GET['md5']
        match = re.match('^[0-9a-f]{32}$', md5)
        system = request.GET['system']
        if system != 'android':
            return make_api_response({'error': 'This API only supports for Android'}, OK)
        if match:
            manifest = StaticAnalyzerAndroid.get_manifest_analysis(md5)
            if match is not None:
                return make_api_response({'count': len(manifest), 'list': manifest}, OK)
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
        md5 = request.GET['md5']
        match = re.match('^[0-9a-f]{32}$', md5)
        system = request.GET['system']
        if match:
            code_analysis = {}
            if system == 'android':
                code_analysis = StaticAnalyzerAndroid.get_code_analysis(md5)
            elif system == 'ios':
                code_analysis = StaticAnalyzerIOS.get_code_analysis(md5)
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


@request_method(['GET'])
def api_file_analysis(request):
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


@request_method(['GET'])
def api_app_permissions(request):
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


@request_method(['GET'])
def api_binary_analysis(request):
    try:
        md5 = request.GET['md5']
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

