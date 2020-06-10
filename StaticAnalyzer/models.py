import logging
from django.db import models

# Create your models here.
logger = logging.getLogger(__name__)


class RecentScansDB(models.Model):
    FILE_NAME = models.CharField(max_length=260)
    MD5 = models.CharField(max_length=32)
    URL = models.URLField()
    TIMESTAMP = models.DateTimeField()
    APP_NAME = models.CharField(max_length=260)
    PACKAGE_NAME = models.CharField(max_length=260)
    VERSION_NAME = models.CharField(max_length=50)


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
    def get_app_info(cls, md5):
        logger.info("get_app_info of %s" % md5)
        try:
            db_entry = cls.objects.get(MD5=md5)
            app_info = {
                'file_name': db_entry.FILE_NAME,
                'size': db_entry.SIZE,
                'md5': db_entry.MD5,
                'sha1': db_entry.SHA1,
                'sha256': db_entry.SHA256,
                'app_name': db_entry.APP_NAME,
                'package_name': db_entry.PACKAGE_NAME,
                'main_activity': db_entry.MAIN_ACTIVITY,
                'target_sdk': db_entry.TARGET_SDK,
                'max_sdk': db_entry.MAX_SDK,
                'min_sdk': db_entry.MIN_SDK,
                'version_name': db_entry.VERSION_NAME,
                'version_code': db_entry.VERSION_CODE
            }
            return app_info
        except:
            logger.info("error get_app_info of %s" % md5)
            return None

    @classmethod
    def get_app_store(cls, md5):
        try:
            logger.info("get_app_store of %s" % md5)
            db_entry = cls.objects.get(MD5=md5)
            app_store_info = eval(db_entry.PLAYSTORE_DETAILS)
            return app_store_info
        except:
            logger.info("error get_app_store of %s" % md5)
            return None

    @classmethod
    def get_security_overview(cls, md5):
        try:
            logger.info("get_security_overview of %s" % md5)
            db_entry = cls.objects.get(MD5=md5)
            mani_high = mani_medium = mani_info = 0
            manifest = eval(db_entry.MANIFEST_ANALYSIS)
            for item in manifest:
                if item['stat'] == 'high':
                    mani_high = mani_high + 1
                elif item['stat'] == 'medium':
                    mani_medium = mani_medium + 1
                elif item['stat'] == 'info':
                    mani_info = mani_info + 1
            code_high = code_good = code_warning = code_info = 0
            code_analysis = eval(db_entry.CODE_ANALYSIS)
            if code_analysis and 'items' in code_analysis.keys():
                for _, details in code_analysis['items']:
                    if details['level'] == 'high':
                        code_high = code_high + 1
                    elif details['level'] == 'good':
                        code_good = code_good + 1
                    elif details['level'] == 'warning':
                        code_warning = code_warning + 1
                    elif details['level'] == 'info':
                        code_info = code_info + 1
            binary_high = binary_medium = binary_info = 0
            binary = eval(db_entry.BINARY_ANALYSIS)
            for item in binary:
                if item['stat'] == 'high':
                    binary_high = binary_high + 1
                elif item['stat'] == 'medium':
                    binary_medium = binary_medium + 1
                elif item['stat'] == 'info':
                    binary_info = binary_info + 1

            security_overview = {
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

            return security_overview
        except:
            logger.info("error get_security_overview of %s" % md5)
            return None

    @classmethod
    def get_code_analysis(cls, md5):
        logger.info("get_code_analysis of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            code_analysis = eval(data_entry.CODE_ANALYSIS)
            return code_analysis
        except:
            logger.info("get_code_analysis error %s" % md5)
            return None

    @classmethod
    def get_binary_analysis(cls, md5):
        logger.info("get_binary_analysis of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            binary_analysis = eval(data_entry.BINARY_ANALYSIS)
            return binary_analysis
        except:
            logger.info("get_binary_analysis error %s" % md5)
            return None

    @classmethod
    def get_components_activities(cls, md5):
        logger.info("get_components_activities of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            activities = eval(data_entry.ACTIVITIES)
        except:
            logger.info("get_components_activities error %s" % md5)
            return None
        return activities

    @classmethod
    def get_components_services(cls, md5):
        logger.info("get_components_servicees of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            services = data_entry.SERVICES
        except:
            logger.info("get_components_servicees error %s" % md5)
            return None
        return services

    @classmethod
    def get_components_receivers(cls, md5):
        logger.info("get_components_receivers of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            receivers = data_entry.RECEIVERS
        except:
            logger.info("get_components_receivers error %s" % md5)
            return None
        return receivers

    @classmethod
    def get_components_providers(cls, md5):
        logger.info("get_components_providers of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            providers = data_entry.PROVIDERS
        except:
            logger.info("get_components_providers error %s" % md5)
            return None
        return providers

    @classmethod
    def get_components_libraries(cls, md5):
        logger.info("get_components_libraries of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            libraries = eval(data_entry.LIBRARIES)
        except:
            logger.info("get_components_libraries error %s" % md5)
            return None
        return libraries

    @classmethod
    def get_components_files(cls, md5):
        logger.info("get_components_files of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            files = eval(data_entry.FILES)
        except:
            logger.info("get_components_files error %s" % md5)
            return None
        return files

    @classmethod
    def get_domain_analysis(cls, md5):
        logger.info("get_components_files of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            domains = eval(data_entry.DOMAINS)
            domain_analysis = []
            for key, value in domains.items():
                bad = value.get('bad', None)
                if bad is None:
                    continue
                domain_entry = {'domain': key,
                                'info': value,
                                'bad': bad}
                domain_analysis.append(domain_entry)
            for i in range(0, len(domain_analysis) - 1):
                for j in range(i + 1, len(domain_analysis)):
                    if domain_analysis[i]['bad'] == 'yes' and domain_analysis[j]['bad'] == 'no':
                        temp = domain_analysis[i]
                        domain_analysis[i] = domain_analysis[j]
                        domain_analysis[j] = temp
        except:
            logger.info("get_components_files error %s" % md5)
            return None

    @classmethod
    def get_manifest_analysis(cls, md5):
        logger.info("get_components_files of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            manifest = eval(data_entry.MANIFEST_ANALYSIS)
            return manifest
        except:
            logger.info("get_components_files error %s" % md5)
            return None

    @classmethod
    def get_file_analysis(cls, md5):
        logger.info("get_file_analysis of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            file_analysis = eval(data_entry.FILE_ANALYSIS)
            return file_analysis
        except:
            logger.info("get_file_analysis error %s" % md5)
            return None

    @classmethod
    def get_app_permissions(cls, md5):
        logger.info("get_app_permissions of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            permissions = eval(data_entry.PERMISSIONS)
            return permissions
        except:
            logger.info("get_app_permissions error %s" % md5)
            return None


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

    @classmethod
    def get_app_info(cls, md5):
        logger.info("ios get_app_info of %s" % md5)
        try:
            db_entry = cls.objects.get(MD5=md5)
            app_info = {
                'file_name': db_entry.FILE_NAME,
                'size': db_entry.SIZE,
                'md5': db_entry.MD5,
                'sha1': db_entry.SHA1,
                'sha256': db_entry.SHA256,
                'app_name': db_entry.APP_NAME,
                'app_type': db_entry.APP_TYPE,
                'identifier': db_entry.BUNDLE_ID,
                'sdk_name': db_entry.SDK_NAME,
                'version': db_entry.APP_VERSION,
                'build': db_entry.BUILD,
                'platform': db_entry.PLATFORM,
                'min_os_version': db_entry.MIN_OS_VERSION,
                'supported_platform': eval(db_entry.BUNDLE_SUPPORTED_PLATFORMS),
            }
            return app_info
        except:
            logger.info("error get_app_info of %s" % md5)
            return None

    @classmethod
    def get_app_store(cls, md5):
        try:
            logger.info("get_app_store of %s" % md5)
            db_entry = cls.objects.get(MD5=md5)
            app_stor_info = eval(db_entry.APPSTORE_DETAILS)
            return app_stor_info
        except:
            logger.info("error get_app_store of %s" % md5)
            return None

    @classmethod
    def get_security_overview(cls, md5):
        try:
            logger.info("get_security_overview of %s" % md5)
            db_entry = cls.objects.get(MD5=md5)

            ats_secure = ats_insecure = ats_warning = ats_info = 0
            ats = eval(db_entry.ATS_ANALYSIS)
            for item in ats:
                if item['status'] == 'secure':
                    ats_secure = ats_secure + 1
                elif item['status'] == 'insecure':
                    ats_insecure = ats_insecure + 1
                elif item['status'] == 'warning':
                    ats_warning = ats_warning + 1
                elif item['status'] == 'info':
                    ats_info = ats_info + 1
            binary_high = binary_good = binary_warning = binary_info = 0
            bns = eval(db_entry.BINARY_ANALYSIS)
            for key in bns:
                details = bns[key]
                if details['level'] == 'high':
                    binary_high = binary_high + 1
                elif details['level'] == 'good':
                    binary_good = binary_good + 1
                elif details['level'] == 'warning':
                    binary_warning = binary_warning + 1
                elif details['level'] == 'info':
                    binary_info = binary_info + 1

            security_overview = {
                'ats': {
                    'secure': ats_secure,
                    'insecure': ats_insecure,
                    'warning': ats_warning,
                    'info': ats_info,
                },
                'binary': {
                    'high': binary_high,
                    'secure': binary_good,
                    'warning': binary_warning,
                    'info': binary_info
                },
            }
            return security_overview
        except:
            logger.info("error get_security_overview of %s" % md5)
            return None

    @classmethod
    def get_code_analysis(cls, md5):
        logger.info("get_code_analysis of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            code_analysis = eval(data_entry.CODE_ANALYSIS)
            return code_analysis
        except:
            logger.info("get_code_analysis error %s" % md5)
            return None

    @classmethod
    def get_binary_analysis(cls, md5):
        logger.info("get_binary_analysis of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            binary_analysis = eval(data_entry.BINARY_ANALYSIS)
            binary_list = []
            for key, value in binary_analysis.items():
                temp = {key: value}
                binary_list.append(temp)
            return binary_list
        except:
            logger.info("get_binary_analysis error %s" % md5)
            return None

    @classmethod
    def get_file_analysis(cls, md5):
        logger.info("get_file_analysis of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            file_analysis = eval(data_entry.FILE_ANALYSIS)
            return file_analysis
        except:
            logger.info("get_file_analysis error %s" % md5)
            return None

    @classmethod
    def get_app_permissions(cls, md5):
        logger.info("get_app_permissions of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            permissions = eval(data_entry.PERMISSIONS)
            return permissions
        except:
            logger.info("get_app_permissions error %s" % md5)
            return None

    @classmethod
    def get_libraries(cls, md5):
        logger.info("get_app_permissions of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            permissions = eval(data_entry.PERMISSIONS)
            return permissions
        except:
            logger.info("get_app_permissions error %s" % md5)
            return None

    @classmethod
    def get_components_libraries(cls, md5):
        logger.info("get_components_libraries of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            libraries = eval(data_entry.LIBRARIES)
        except:
            logger.info("get_components_libraries error %s" % md5)
            return None
        return libraries

    @classmethod
    def get_components_files(cls, md5):
        logger.info("get_components_files of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            files = eval(data_entry.FILES)
        except:
            logger.info("get_components_files error %s" % md5)
            return None
        return files

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
