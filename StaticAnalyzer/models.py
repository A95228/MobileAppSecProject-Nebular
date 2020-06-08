import logging

from django.db import models
# Unsused for now.
from django.core.paginator import Paginator


logger = logging.getLogger(__name__)


class RecentScansDB(models.Model):
    FILE_NAME = models.CharField(max_length=260)
    MD5 = models.CharField(max_length=32)
    URL = models.URLField()
    TIMESTAMP = models.DateTimeField()
    APP_NAME = models.CharField(max_length=260)
    PACKAGE_NAME = models.CharField(max_length=260)
    VERSION_NAME = models.CharField(max_length=50)


    @classmethod
    def get_recent_scans(cls):
        scans = cls.objects.all().order_by("-TIMESTAMP")
        if scans.count() == 0:
            return None
        scans_values = scans.values(
            "APP_NAME",
            "FILE_NAME",
            "TIMESTAMP",
            "MD5",
            "PACKAGE_NAME",
            "URL",
            "VERSION_NAME"
        )
        try:
            to_return = list(scans_values)
        except Exception as e:
            e = str(e) + " Sending back None"
            logger.warning(msg=e)
            return None
        else:
            return to_return


class StaticAnalyzerAndroid(models.Model):
    FILE_NAME = models.CharField(max_length=260)
    APP_NAME = models.CharField(max_length=255)
    APP_TYPE = models.CharField(max_length=20, default='')
    SIZE = models.CharField(max_length=50)
    MD5 = models.CharField(max_length=32)
    SHA1 = models.CharField(max_length=40)
    SHA256 = models.CharField(max_length=64)
    PACKAGE_NAME = models.CharField(max_length=40)
    MAIN_ACTIVITY = models.CharField(max_length=300)
    EXPORTED_ACTIVITIES = models.TextField()
    BROWSABLE_ACTIVITIES = models.TextField()
    ACTIVITIES = models.TextField()
    RECEIVERS = models.TextField()
    PROVIDERS = models.TextField()
    SERVICES = models.TextField()
    LIBRARIES = models.TextField()
    TARGET_SDK = models.CharField(max_length=50)
    MAX_SDK = models.CharField(max_length=50)
    MIN_SDK = models.CharField(max_length=50)
    VERSION_NAME = models.CharField(max_length=100)
    VERSION_CODE = models.CharField(max_length=50)
    ICON_HIDDEN = models.BooleanField(default=False)
    ICON_FOUND = models.BooleanField(default=False)
    PERMISSIONS = models.TextField()
    CERTIFICATE_ANALYSIS = models.TextField()
    MANIFEST_ANALYSIS = models.TextField()
    BINARY_ANALYSIS = models.TextField()
    FILE_ANALYSIS = models.TextField()
    ANDROID_API = models.TextField()
    CODE_ANALYSIS = models.TextField()
    URLS = models.TextField()
    DOMAINS = models.TextField()
    EMAILS = models.TextField()
    STRINGS = models.TextField()
    FIREBASE_URLS = models.TextField(default=[])
    FILES = models.TextField()
    EXPORTED_COUNT = models.TextField(default={})
    APKID = models.TextField(default={})
    TRACKERS = models.TextField(default={})
    PLAYSTORE_DETAILS = models.TextField(default={})


    @classmethod
    def get_certificate_analysis_data(cls, md5):
        """Get a certificate return None otherwise"""
        try:
            cert = cls.objects.get(MD5=md5)
            cert = cert.CERTIFICATE_ANALYSIS
        except:
            return None
        else:
            return eval(cert)


    @classmethod
    def get_manifest(cls, md5):
        """Get a manifest return None otherwise"""
        try:
            cert = cls.objects.get(MD5=md5)
            manifest = cert.MANIFEST_ANALYSIS
        except:
            return None
        else:
            manifest = dict(manifest_analysis=eval(manifest))
        finally:
            return manifest


    @classmethod
    def get_recon_data(cls, md5):
        try:
            query = cls.objects.get(MD5=md5)
        except:
            return None
        else:
            data = {
                "emails" : eval(query.EMAILS),
                "firebase_urls" : eval(query.FIREBASE_URLS),
                "trackers" : eval(query.TRACKERS),
                "urls" : eval(query.URLS)
            }
        return data


    @classmethod
    def get_domains_data(cls, md5):
        """Get domains"""
        try:
            query = cls.objects.get(MD5=md5)
        except:
            return None
        else:
            countries = []
            try:
                domains = eval(query.DOMAINS)
                for key, value in domains.items():
                    holder = {}
                    geolocation = value.get("geolocation", None)
                    if geolocation is None:
                        holder[key] = {}
                        for k in value.keys():
                            if k in ('good', 'bad'):
                                holder[key][k] = value.get(k, None)
                        holder[key]["domain"] = key 
                        countries.append(holder)
                        continue
                    country = geolocation.pop("country_long")
                    holder[country] = {}
                    holder[country]["domain"] = key
                    for k in value.keys():
                        if k in ('good', 'bad'):
                            holder[country][k] = value.get(k, None)
                    holder[country].update(geolocation)
                    countries.append(holder)
            except:
                return None
            return {"countries" : countries}
            

class StaticAnalyzerIOS(models.Model):
    FILE_NAME = models.CharField(max_length=255)
    APP_NAME = models.CharField(max_length=255)
    APP_TYPE = models.CharField(max_length=20, default='')
    SIZE = models.CharField(max_length=50)
    MD5 = models.CharField(max_length=32)
    SHA1 = models.CharField(max_length=40)
    SHA256 = models.CharField(max_length=64)
    BUILD = models.TextField()
    APP_VERSION = models.CharField(max_length=100)
    SDK_NAME = models.CharField(max_length=50)
    PLATFORM = models.CharField(max_length=50)
    MIN_OS_VERSION = models.CharField(max_length=50)
    BUNDLE_ID = models.TextField()
    BUNDLE_URL_TYPES = models.TextField(default=[])
    BUNDLE_SUPPORTED_PLATFORMS = models.CharField(max_length=50)
    ICON_FOUND = models.BooleanField(default=False)
    INFO_PLIST = models.TextField()
    MACHO_INFO = models.TextField(default={})
    PERMISSIONS = models.TextField(default=[])
    ATS_ANALYSIS = models.TextField(default=[])
    BINARY_ANALYSIS = models.TextField(default=[])
    IOS_API = models.TextField(default={})
    CODE_ANALYSIS = models.TextField(default={})
    FILE_ANALYSIS = models.TextField(default=[])
    LIBRARIES = models.TextField(default=[])
    FILES = models.TextField(default=[])
    URLS = models.TextField(default=[])
    DOMAINS = models.TextField(default={})
    EMAILS = models.TextField(default=[])
    STRINGS = models.TextField(default=[])
    FIREBASE_URLS = models.TextField(default=[])
    APPSTORE_DETAILS = models.TextField(default={})


class StaticAnalyzerWindows(models.Model):
    FILE_NAME = models.CharField(max_length=260)
    APP_NAME = models.CharField(max_length=260)
    PUBLISHER_NAME = models.TextField()
    SIZE = models.CharField(max_length=50)
    MD5 = models.CharField(max_length=32)
    SHA1 = models.CharField(max_length=40)
    SHA256 = models.CharField(max_length=64)
    APP_VERSION = models.TextField()
    ARCHITECTURE = models.TextField()
    COMPILER_VERSION = models.TextField()
    VISUAL_STUDIO_VERSION = models.TextField()
    VISUAL_STUDIO_EDITION = models.TextField()
    TARGET_OS = models.TextField()
    APPX_DLL_VERSION = models.TextField()
    PROJ_GUID = models.TextField()
    OPTI_TOOL = models.TextField()
    TARGET_RUN = models.TextField()
    FILES = models.TextField()
    STRINGS = models.TextField()
    BINARY_ANALYSIS = models.TextField()
    BINARY_WARNINGS = models.TextField()


