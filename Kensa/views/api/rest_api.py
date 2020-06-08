# -*- coding: utf_8 -*-
"""Kensa REST API V 1."""
import logging
import os
import re
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
from StaticAnalyzer.models import StaticAnalyzerAndroid
from django.contrib.auth.decorators import permission_required

from django.conf import settings
from Kensa.utils import (file_size)
from StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry)
from StaticAnalyzer.views.android.manifest_analysis import (get_manifest, manifest_data)

from StaticAnalyzer.views.shared_func import (hash_gen, unzip)

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
@csrf_exempt
def api_app_info(request):
    """Do static analysis on an request and save to db."""
    try:

        typ = request.GET['type']
        checksum = request.GET['checksum']
        filename = request.GET['name']

        # Input validation
        app_dic = {}
        match = re.match('^[0-9a-f]{32}$', checksum)
        if match and (filename.lower().endswith('.apk') or filename.lower().endswith('.zip')) and (
                typ in ['zip', 'apk']):
            base_dir = settings.BASE_DIR  # BASE DIR
            app_dic['app_name'] = filename  # APP ORGINAL NAME
            app_dic['md5'] = checksum  # MD5
            app_dir = os.path.join(settings.UPLD_DIR, app_dic['md5'] + '/')  # APP DIRECTORY

            tools_dir = os.path.join(base_dir, 'StaticAnalyzer/tools/')  # TOOLS DIR

            logger.info('Starting Analysis on : %s', app_dic['app_name'])

            if typ == 'apk':
                db_entry = StaticAnalyzerAndroid.objects.filter(
                    MD5=app_dic['md5'])
                if db_entry.exists():
                    context = get_context_from_db_entry(db_entry)
                    ok_response_dic = {
                        'file_name': context['file_name'],
                        'size': context['size'],
                        'md5': context['md5'],
                        'sha1': context['sha1'],
                        'sha256': context['sha256'],
                        'app_name': context['app_name'],
                        'package_name': context['package_name'],
                        'main_activity': context['main_activity'],
                        'target_sdk': context['target_sdk'],
                        'max_sdk': context['max_sdk'],
                        'min_sdk': context['min_sdk'],
                        'version_name': context['version_name'],
                        'version_code': context['version_code']
                    }
                    return make_api_response(ok_response_dic, OK)
                else:
                    app_file = app_dic['md5'] + '.apk'  # NEW FILENAME
                    app_path = (app_dir + app_file)  # APP PATH

                    app_dic['size'] = str(
                        file_size(app_path)) + 'MB'  # FILE SIZE
                    app_dic['sha1'], app_dic['sha256'] = hash_gen(app_path)

                    app_file = app_dic['md5'] + '.apk'  # NEW FILENAME
                    app_path = (app_dir + app_file)  # APP PATH
                    files = unzip(app_path, app_dir)
                    if not files:
                        msg = 'APK file is invalid or corrupt'
                        return make_api_response({'error': msg}, INTERNAL_SERVER_ERR)
                    logger.info('APK Extracted')
                    parsed_xml = get_manifest(app_path, app_dir, tools_dir, '', True, )

                    # get app_name
                    app_dic['real_name'] = get_app_name(
                        app_path, app_dir, tools_dir,
                        True,
                    )
                    man_data_dic = manifest_data(parsed_xml)
                    ok_response_dic = make_app_info_response(app_dic, man_data_dic)
                    return make_api_response(ok_response_dic, OK)
            elif typ == 'zip':
                db_entry = StaticAnalyzerAndroid.objects.filter(MD5=app_dic['md5'])
                if db_entry.exists():
                    context = get_context_from_db_entry(db_entry)
                else:
                    app_file = app_dic['md5'] + '.zip'  # NEW FILENAME
                    app_path = app_dir + app_file  # APP PATH
                    files = unzip(app_path, app_dir)
                    pro_type, valid = valid_android_zip(app_dir)
                    if valid and pro_type == 'ios':
                        logger.info('Redirecting to iOS Source Code Analyzer')
                        return make_api_response({'type': 'ios'}, BAD_REQUEST)
                    if valid and (pro_type in ['eclipse', 'studio']):
                        app_dic['size'] = str(file_size(app_path)) + 'MB'  # FILE SIZE
                        app_dic['sha1'], app_dic[
                            'sha256'] = hash_gen(app_path)
                        parsed_xml = get_manifest('', app_dir, tools_dir, pro_type, False)
                        # get app_name
                        app_dic['real_name'] = get_app_name(
                            app_path, app_dir, tools_dir, False, )
                        man_data_dic = manifest_data(parsed_xml)
                        ok_response_dic = make_app_info_response(app_dic, man_data_dic)
                        return make_api_response(ok_response_dic, OK)
        return make_api_response({'error': 'Input File Error'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error Performing Static Analysis')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)


@request_method(['GET'])
@csrf_exempt
def api_app_store(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        if match:
            db_entry = StaticAnalyzerAndroid.objects.filter(
                MD5=md5)
            if db_entry.exists():
                context = get_context_from_db_entry(db_entry)
                ok_response_dic = {
                    'playstore_details': context['playstore_details'],
                }
                return make_api_response(ok_response_dic, OK)
            return make_api_response({'error': 'Data Entry not exist'}, OK)
        else:
            return make_api_response({'error': 'HASH err'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error calling api_app_store')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)


@request_method(['GET'])
@csrf_exempt
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
@csrf_exempt
def api_security_overview(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        if match:
            db_entry = StaticAnalyzerAndroid.objects.filter(
                MD5=md5)
            if db_entry.exists():
                context = get_context_from_db_entry(db_entry)
                mani_high = mani_medium = mani_info = 0
                for item in context['manifest_analysis']:
                    if item['stat'] == 'high':
                        mani_high = mani_high + 1
                    elif item['stat'] == 'medium':
                        mani_medium = mani_medium + 1
                    elif item['stat'] == 'info':
                        mani_info = mani_info + 1

                code_high = code_good = code_warning = code_info = 0
                if context['code_analysis'] and 'items' in context['code_analysis'].keys():
                    for _, details in context['code_analysis']['items']:
                        if details['level'] == 'high':
                            code_high = code_high + 1
                        elif details['level'] == 'good':
                            code_good = code_good + 1
                        elif details['level'] == 'warning':
                            code_warning = code_warning + 1
                        elif details['level'] == 'info':
                            code_info = code_info + 1

                binary_high = binary_medium = binary_info = 0
                for item in context['binary_analysis']:
                    if item['stat'] == 'high':
                        binary_high = binary_high + 1
                    elif item['stat'] == 'medium':
                        binary_medium = binary_medium + 1
                    elif item['stat'] == 'info':
                        binary_info = binary_info + 1

                resp = {
                    'manifest': {
                        'high': mani_high,
                        'medium': mani_medium,
                        'info': mani_info
                        },
                    'code': {
                        'high': code_high,
                        'good': code_good,
                        'warning': code_warning,
                        'info': code_info
                        },
                    'binary': {
                        'high': binary_high,
                        'medium': binary_medium,
                        'info': binary_info
                    }
                }
                return make_api_response(resp, OK)
            return make_api_response({'msg': 'Not exist'}, OK)
        else:
            return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error calling api_security_overview')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)


@request_method(['GET'])
@csrf_exempt
def api_malware_overview(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        if match:
            db_entry = StaticAnalyzerAndroid.objects.filter(
                MD5=md5)
            if db_entry.exists():
                context = get_context_from_db_entry(db_entry)
                _, security_score = score(context['code_analysis'])
                ok_response_dic = {
                    'security_score': security_score,
                }
                return make_api_response(ok_response_dic, OK)
            return make_api_response({'msg': 'Not exist'}, OK)
        else:
            return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error calling api_malware_overview')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)


@request_method(['GET'])
@csrf_exempt
def api_components(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        if match:
            db_entry = StaticAnalyzerAndroid.objects.filter(
                MD5=md5)
            if db_entry.exists():
                context = get_context_from_db_entry(db_entry)
                resp = {
                    'activity': {
                        'count': len(context['activities']),
                        'list': context['activities']
                    },
                    'services': {
                        'count': len(context['services']),
                        'list': context['services']
                    },
                    'receivers': {
                        'count': len(context['receivers']),
                        'list': context['receivers']
                    },
                    'providers': {
                        'count': len(context['providers']),
                        'list': context['providers']
                    },
                    'libraries': {
                        'count': len(context['libraries']),
                        'list': context['libraries']
                    },
                    'files': {
                        'count': len(context['files']),
                        'list': context['files']
                    },
                }
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
@csrf_exempt
def api_domain_analysis(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        if match:
            db_entry = StaticAnalyzerAndroid.objects.filter(
                MD5=md5)
            if db_entry.exists():
                context = get_context_from_db_entry(db_entry)
                if context['domains']:
                    return make_api_response(context['domains'], OK)
            return make_api_response({'msg': 'Not exist'}, OK)
        else:
            return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error calling api_malware_overview')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)


@request_method(['GET'])
@csrf_exempt
def api_manifest_analysis(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        if match:
            db_entry = StaticAnalyzerAndroid.objects.filter(
                MD5=md5)
            if db_entry.exists():
                context = get_context_from_db_entry(db_entry)
                resp = {
                    'count': len(context['manifest_analysis']),
                    'list': context['manifest_analysis']
                }
                return make_api_response(resp, OK)
            return make_api_response({'msg': 'Not exist'}, OK)
        else:
            return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error calling api_security_overview')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)


@request_method(['GET'])
@csrf_exempt
def api_code_analysis(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        if match:
            db_entry = StaticAnalyzerAndroid.objects.filter(
                MD5=md5)
            if db_entry.exists():
                context = get_context_from_db_entry(db_entry)
                if context['code_analysis'] and 'items' in context['code_analysis'].keys():
                    resp = {
                        'count': len(context['code_analysis']['items']),
                        'list': context['code_analysis']['items']
                    }
                    return make_api_response(resp, OK)
            return make_api_response({'msg': 'Not exist'}, OK)
        else:
            return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error calling api_security_overview')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)


@request_method(['GET'])
@csrf_exempt
def api_app_permissions(request):
    try:
        md5 = request.GET['checksum']
        match = re.match('^[0-9a-f]{32}$', md5)
        if match:
            db_entry = StaticAnalyzerAndroid.objects.filter(
                MD5=md5)
            if db_entry.exists():
                context = get_context_from_db_entry(db_entry)
                if context['permissions']:
                    return make_api_response(context['permissions'], OK)
            return make_api_response({'msg': 'Not exist'}, OK)
        else:
            return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error calling api_security_overview')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)


@request_method(['GET'])
@csrf_exempt
def api_binary_analysis(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        if match:
            db_entry = StaticAnalyzerAndroid.objects.filter(
                MD5=md5)
            if db_entry.exists():
                context = get_context_from_db_entry(db_entry)
                resp = {
                    'count': len(context['binary_analysis']),
                    'list': context['binary_analysis']
                }
                return make_api_response(resp, OK)
            return make_api_response({'msg': 'Not exist'}, OK)
        else:
            return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error calling api_security_overview')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)


@request_method(['GET'])
@csrf_exempt
def api_file_analysis(request):
    try:
        md5 = request.GET['hash']
        match = re.match('^[0-9a-f]{32}$', md5)
        if match:
            db_entry = StaticAnalyzerAndroid.objects.filter(
                MD5=md5)
            if db_entry.exists():
                context = get_context_from_db_entry(db_entry)
                resp = {
                    'count': len(context['file_analysis']),
                    'list': context['file_analysis']
                }
                return make_api_response(resp, OK)
            return make_api_response({'msg': 'Not exist'}, OK)
        else:
            return make_api_response({'error': 'HASH error'}, BAD_REQUEST)
    except Exception as excep:
        logger.exception('Error calling api_security_overview')
        msg = str(excep)
        exp = excep.__doc__
        return make_api_response({'error': msg}, BAD_REQUEST)
