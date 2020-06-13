# -*- coding: utf_8 -*-
import hashlib
import logging
import pdb
import os

from django.conf import settings
from django.utils import timezone

from StaticAnalyzer.models import RecentScansDB
from django.contrib.auth.decorators import permission_required
from StaticAnalyzer.views.android.static_analyzer import static_analyzer_android
from StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios_api

logger = logging.getLogger(__name__)


def add_to_recent_scan(name, md5, url, organization_id):
    """Add Entry to Database under Recent Scan."""
    try:
        db_obj = RecentScansDB.objects.filter(MD5=md5)
        if not db_obj.exists():
            new_db_obj = RecentScansDB(
                FILE_NAME=name,
                MD5=md5,
                URL=url,
                TIMESTAMP=timezone.now(),
                ORGANIZATION_ID=organization_id
            )
            new_db_obj.save()
            logger.info("Scanned saved")
    except Exception as error:
        logger.exception('Adding Scan URL to Database')
        error = str(error)
        logger.info(error)


def handle_uploaded_file(filecnt, typ):
    """Write Uploaded File."""
    md5 = hashlib.md5()  # modify if crash for large
    for chunk in filecnt.chunks():
        md5.update(chunk)
    md5sum = md5.hexdigest()
    anal_dir = os.path.join(settings.UPLD_DIR, md5sum + '/')
    if not os.path.exists(anal_dir):
        os.makedirs(anal_dir)
    with open(anal_dir + md5sum + typ, 'wb+') as destination:
        for chunk in filecnt.chunks():
            destination.write(chunk)
    return md5sum


class Scanning(object):

    def __init__(self, request):
        self.request = request
        self.file = request.FILES['file']
        self.file_name = request.FILES['file'].name


    def scan_apk(self):
        """Android APK."""
        md5 = handle_uploaded_file(self.file, '.apk')
        url = 'StaticAnalyzer/?name={}&type=apk&checksum={}'.format(
                    self.file_name,
                    md5
                )

        data = {
            'url': url,
            'status': 'success',
            'hash': md5,
            'scan_type': 'apk',
            'file_name': self.file_name,
        }
        
        add_to_recent_scan(
            self.file_name,
            md5,
            data['url'],
            self.request.user.organization
        )

        logger.info('Uploaded file %s' % self.file_name)

        return data


    def scan_zip(self):
        """Android /iOS Zipped Source."""
        md5 = handle_uploaded_file(self.file, '.zip')
        url = 'StaticAnalyzer/?name={}&type=zip&checksum={}'.format(
            self.file_name, md5)
        data = {
            'url': url,
            'status': 'success',
            'hash': md5,
            'scan_type': 'zip',
            'file_name': self.file_name,
        }

        add_to_recent_scan(
            self.file_name, 
            md5, 
            data['url'], 
            self.request.user.organization
        )

        logger.info('Uploded file %s' % self.file_name)
        return data


    def scan_ipa(self):
        """IOS Binary."""
        md5 = handle_uploaded_file(self.file, '.ipa')
        url = 'StaticAnalyzer_iOS/?name={}&type=ipa&checksum={}'.format(
            self.file_name, md5)
        data = {
            'hash': md5,
            'scan_type': 'ipa',
            'file_name': self.file_name,
            'url': url,
            'status': 'success',
        }

        add_to_recent_scan(
            self.file_name,
            md5,
            data['url'],
            self.request.user.organization
        )

        logger.info('Uploaded IOS %s' % self.file_name)
        return data


    def scan_appx(self):
        """Windows appx."""
        md5 = handle_uploaded_file(self.file, '.appx')
        url = 'StaticAnalyzer_Windows/?name={}&type=appx&checksum={}'.format(
            self.file_name, md5)
        data = {
            'hash': md5,
            'scan_type': 'appx',
            'file_name': self.file_name,
            'url': url,
            'status': 'success',
        }

        add_to_recent_scan(
            self.file_name,
            md5, 
            data['url'],
            self.request.user.organization
        )
        logger.info('Uploaded file Windows appx %s' % self.file_name)
        return data
