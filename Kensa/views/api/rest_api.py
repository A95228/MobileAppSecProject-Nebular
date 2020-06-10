# -*- coding: utf_8 -*-
"""Kensa REST API V 1."""
import pdb 
import re

from django.core.paginator import Paginator
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework.views import APIView

from Kensa.utils import api_key
from Kensa.views.api import tools, serializers
from Kensa.views.helpers import request_method
from Kensa.views.home import RecentScans, Upload, delete_scan

from StaticAnalyzer.views.android import view_source
from StaticAnalyzer.views.android.static_analyzer import static_analyzer
from StaticAnalyzer.views.android.java import run, api_run_java_code
from StaticAnalyzer.views.ios import view_source as ios_view_source
from StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios
from StaticAnalyzer.views.shared_func import pdf
from StaticAnalyzer.views.windows import windows
from StaticAnalyzer import models


BAD_REQUEST = 400
OK = 200
NOT_FOUND = 404
SYSTEMS = [
    "ios",
    "android"
]


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
    ios_md5s = models.StaticAnalyzerIOS.get_md5s(md5)
    android_md5s = models.StaticAnalyzerAndroid.get_md5s(md5)
    search_results = tools.merge_search(ios_md5s, android_md5s)
    
    if not len(search_results) > 0:
        return make_api_response({"error" : "0 search results for %s." % md5},
            status=NOT_FOUND)
        
    return make_api_response({"results" : search_results}, status=OK)


@request_method(["GET"])
def api_get_recent_scans(request):
    """Get Recent Scans """
    data = models.RecentScansDB.get_recent_scans()
    if data is not None:
        if isinstance(data, dict):
            return make_api_response(data=data, status=OK)
        return JsonResponse(data=data, safe=False, status=OK) # strange case
    return make_api_response(data={"error" : "no data"}, status=BAD_REQUEST)


@request_method(["GET"])
def api_get_signer_certificate(request):
    """Get certificate"""
    if request.GET.get("md5", None) is None:
        return make_api_response(data={"error" : "missing md5"}, 
            status=BAD_REQUEST)

    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return make_api_response(data={"error" : "Invalid identifier"}, 
            status=BAD_REQUEST)
    
    md5 = request.GET["md5"]

    try:
        data = models.StaticAnalyzerAndroid.get_certificate_analysis_data(md5)
    except:
        return make_api_response({"error" : "contact sysadmin"},
            status=500)

    if data is None:
        return make_api_response(data={"info" : "No data to preview"}, 
            status=NOT_FOUND)

    return make_api_response(data=data, status=OK)
    

@request_method(["GET"])
def api_get_manifest(request):
    """Get manifest"""
    if request.GET.get("md5", None) is None:
        return make_api_response(data={"error" : "missing md5"}, 
            status=BAD_REQUEST)

    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return make_api_response(data={"error" : "invalid identifier"}, 
            status=NOT_FOUND)

    md5 = request.GET["md5"]

    try:
        data = models.StaticAnalyzerAndroid.get_manifest(md5)
    except:
        return make_api_response({"error" : "contact sysadmin"},
            status=500)

    if data is None:
        return make_api_response(data={"info" : "No data to preview"})

    return JsonResponse(data=data, status=OK)


@request_method(["GET"])
def api_get_domains_data(request):
    """Get domains data"""
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
            status=BAD_REQUEST)
    
    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return make_api_response({"error" : "Invalid identifier"}, 
            status=BAD_REQUEST)

    md5 = request.GET["md5"]
    
    try:
        data = models.StaticAnalyzerAndroid.get_domains_data(md5)
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
#       /api/v1/code/java?md5=<md5>&page=<page_num> 
#       /api/v1/code/smali?md5=<md5>&page=<page_num>
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


@request_method(["GET"])
def api_get_java_code(request):
    """Get a list of java code files"""
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
            status=BAD_REQUEST)
    
    if request.GET.get("type", None) is None:
        return make_api_response({"error" : "Missing type"}, 
            status=BAD_REQUEST)
    
    if request.GET.get("page", None) is not None:
        if re.match(r"^\d+$", request.GET["page"]):
            page = request.GET["page"]
        else:
            page = 1
    else:
        page = 1

    # get files
    try:
        ctx = api_run_java_code(request)
    except:
        return make_api_response({"error" : "contact sysadmin"},
            status=500)

    if 'error' in ctx:
        return make_api_response(data=ctx, status=BAD_REQUEST)

    # inject pagination
    try:
        files = models.StaticAnalyzerAndroid.paginate(ctx["files"], page)
    except:
        pass
    else:
        ctx.update({"files" : files})

    return make_api_response(data=ctx, status=OK)


@request_method(["GET"])
def api_get_smali_code(request):
    """Get smali code"""
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
    
    # get files
    try:
        ctx = tools.get_smali_drop(md5)
    except:
        return make_api_response({"error" : "contact sysadmin"},
            status=500)

    if ctx is None:
        return make_api_response({"error" : "error getting smali files"},
            status=NOT_FOUND)

    # inject pagination
    try:
        files = models.StaticAnalyzerAndroid.paginate(ctx["files"], page)
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
#
#   Examples for routes that are just for Android
#   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#       /api/v1/recon_trackers?md5=<md5>&page=<page_num>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


@request_method(["GET"])
def api_get_recon_emails(request):
    """Get reconnaissance emails or error"""
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
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
        emails = models.StaticAnalyzerAndroid.get_recon_emails(md5, page)
    elif system == "ios":
        emails = models.StaticAnalyzerIOS.get_recon_emails(md5, page)
    
    if emails is None:
        return make_api_response({"error" : "no emails for %s" % md5}, 
            status=NOT_FOUND)

    return make_api_response(emails, status=OK)


@request_method(["GET"])
def api_get_recon_urls(request):
    """Get reconnaissance urls"""
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
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
        urls = models.StaticAnalyzerAndroid.get_recon_urls(md5, page)
    elif system == "ios":
        urls = models.StaticAnalyzerIOS.get_recon_urls(md5, page)
    
    if urls is None:
        return make_api_response({"error" : "no urls for %s" % md5}, 
            status=NOT_FOUND)
    
    return make_api_response(urls, status=OK)


@request_method(["GET"])
def api_get_recon_firebase_db_urls(request):
    """Get recon firebase or error"""
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
        firebase_urls = models.StaticAnalyzerAndroid.get_recon_firebase_db(md5, page)
    elif system == "ios":
        firebase_urls = models.StaticAnalyzerIOS.get_recon_firebase_db(md5, page)

    if firebase_urls is None:
        return make_api_response({"error" : "no firebase urls for %s" % md5}, 
            status=NOT_FOUND)

    return make_api_response(firebase_urls, status=OK)


@request_method(["GET"])
def api_get_recon_trackers(request):
    """Get recon trackers or error"""
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
        trackers = models.StaticAnalyzerAndroid.get_recon_trackers(md5, page)
    except:
        return make_api_response({"error" : "contact sysadmin"},
            status=500)

    if trackers is None:
        return make_api_response({"error" : "no trackers for %s" % md5}, 
            status=NOT_FOUND)

    return make_api_response(trackers, status=OK)

