# -*- coding: utf_8 -*-
"""Kensa REST API V 1."""
import pdb 
import re

from django.core.paginator import Paginator
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

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
def api_get_recent_scans(request):
    """Get Recent Scans """
    data = models.RecentScansDB.get_recent_scans()
    if data is not None:
        if isinstance(data, dict):
            return make_api_response(data=data, status=OK)
        return JsonResponse(data=data, safe=False, status=OK) # strange case
    return make_api_response(data={"error" : "<error here>"}, status=BAD_REQUEST)


@request_method(["GET"])
def api_get_signer_certificate(request):
    """Get certificate"""
    if request.GET.get("md5", None) is None:
        return make_api_response(data={"error" : "missing md5"}, 
            status=BAD_REQUEST)

    id = request.GET["md5"]

    if not re.match(r"^[0-9a-f]{32}$", id):
        return make_api_response(data={"error" : "Invalid identifier"}, 
            status=BAD_REQUEST)

    data = models.StaticAnalyzerAndroid.get_certificate_analysis_data(id)
    if data is None:
        return make_api_response(data={"info" : "No data to preview"}, 
            status=404)
    return make_api_response(data=data, status=OK)
    

@request_method(["GET"])
def api_get_manifest(request):
    """Get manifest"""
    if request.GET.get("md5", None) is None:
        return make_api_response(data={"error" : "missing md5"}, 
            status=BAD_REQUEST)

    id = request.GET["md5"]
    if not re.match(r"^[0-9a-f]{32}$", id):
        return make_api_response(data={"error" : "invalid identifier"}, 
            status=404)

    data = models.StaticAnalyzerAndroid.get_manifest(id)

    if data is None:
        return make_api_response(data={"info" : "No data to preview"})

    return JsonResponse(data=data, status=200)


@request_method(["GET"])
def api_get_domains_data(request):
    """Get domains data"""
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
            status=BAD_REQUEST)

    id = request.GET["md5"]
    
    if not re.match(r"^[0-9a-f]{32}$", id):
        return make_api_response({"error" : "Invalid identifier"}, 
            status=BAD_REQUEST)
    
    data = models.StaticAnalyzerAndroid.get_domains_data(id)
    if data is None:
        return make_api_response({"error": "No data to preview"}, 
            status=404)
    
    return make_api_response(data=data, status=OK)


@request_method(["GET"])
def api_get_java_code(request):
    """Get a list of java code files"""
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
            status=BAD_REQUEST)
    
    if request.GET.get("type", None) is None:
        return make_api_response({"error" : "Missing type"}, 
            status=BAD_REQUEST)
    
    ctx = api_run_java_code(request)
    
    if 'error' in ctx:
        return make_api_response(data=ctx, status=BAD_REQUEST)

    data = serializers.JavaCodeSerializer(ctx)
    return make_api_response(data=data.data, status=OK)


@request_method(["GET"])
def api_get_smali_code(request):
    """Get smali code"""
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
            status=BAD_REQUEST)
    
    id = request.GET["md5"]
    ctx = tools.get_smali_drop(md5=id)
    
    if ctx is None:
        drop = {"error" : "error getting smali files"}
        return make_api_response(data=drop, status=NOT_FOUND)

    data = serializers.JavaCodeSerializer(ctx)
    return make_api_response(data=data.data, status=OK)


@request_method(["GET"])
def api_get_recon_emails(request):
    """Get recon emails or error"""
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
            status=BAD_REQUEST)

    id = request.GET["md5"]

    if not re.match(r"^[0-9a-f]{32}$", id):
        return make_api_response(
            {"error" : "Invalid identifier"}, 
            status=BAD_REQUEST)

    emails = models.StaticAnalyzerAndroid.get_recon_emails(id)

    if emails is None:
        return make_api_response({"error" : "no emails for %s" % id}, 
            status=NOT_FOUND)

    return make_api_response(emails, status=OK)


@request_method(["GET"])
def api_get_recon_urls(request):
    """Get recon urls or error"""
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
            status=BAD_REQUEST)

    id = request.GET["md5"]

    if not re.match(r"^[0-9a-f]{32}$", id):
        return make_api_response({"error" : "Invalid identifier"}, 
            status=BAD_REQUEST)

    urls = models.StaticAnalyzerAndroid.get_recon_urls(md5=id)
    
    if urls is None:
        return make_api_response({"error" : "no emails for %s" % id}, 
            status=NOT_FOUND)
    
    return make_api_response(urls, status=OK)


@request_method(["GET"])
def api_get_recon_firebase_db_urls(request):
    """Get recon firebase or error"""
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, status=BAD_REQUEST)

    id = request.GET["md5"]

    if not re.match(r"^[0-9a-f]{32}$", id):
        return make_api_response({"error" : "Invalid identifier"},
            status=BAD_REQUEST)

    firebase_urls = models.StaticAnalyzerAndroid.get_recon_firebase_db(md5=id)

    if firebase_urls is None:
        return make_api_response({"error" : "no firebase urls for %s" % id}, 
            status=NOT_FOUND)

    return make_api_response(firebase_urls, status=OK)


@request_method(["GET"])
def api_get_recon_trackers(request):
    """Get recon trackers or error"""
    if request.GET.get("md5", None) is None:
        return make_api_response({"error" : "Missing identifier"}, 
            status=BAD_REQUEST)

    id = request.GET["md5"]

    if not re.match(r"^[0-9a-f]{32}$", id):
        return make_api_response({"error" : "Invalid identifier"}, 
            status=BAD_REQUEST)

    trackers = models.StaticAnalyzerAndroid.get_recon_trackers(md5=id)

    if trackers is None:
        return make_api_response({"error" : "no trackers for %s" % id}, 
            status=NOT_FOUND)

    return make_api_response(trackers, status=OK)


@request_method(["GET"])
def api_get_search(request):
    """Get search results"""
    if request.GET.get("md5",None) is None:
        return make_api_response({"error" : "Missing Identifier"}, 
            status=BAD_REQUEST)

    if not re.match(r"^[0-9a-f]{32}$", id):
        return make_api_response({"error" : "Invalid identifier"}, 
            status=BAD_REQUEST)
    
    id = request.GET.get("md5")
