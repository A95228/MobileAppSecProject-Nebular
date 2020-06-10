# noqa: E800
"""
Django settings for Kensa project.

Kensa and Django settings
"""

import imp
import logging
import os

from Kensa.utils import (find_java_binary, first_run,
                         get_kensa_home)

logger = logging.getLogger(__name__)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       KENSA CONFIGURATIONS
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


KENSA_VER = 'v0.0.1 Beta'

BANNER = """
"""  # noqa: W291
# ASCII Standard
# ==============================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(BASE_DIR)
# ==========Kensa Home Directory=================
USE_HOME = False

# True : All Uploads/Downloads will be stored in user's home directory
# False : All Uploads/Downloads will be stored in Kensa root directory
# If you need multiple users to share the scan results set this to False
# ===============================================

Kensa_HOME = get_kensa_home(USE_HOME)
# Logs Directory
LOG_DIR = os.path.join(Kensa_HOME, 'logs/')
# Download Directory
DWD_DIR = os.path.join(Kensa_HOME, 'downloads/')
# Screenshot Directory
SCREEN_DIR = os.path.join(Kensa_HOME, 'downloads/screen/')
# Upload Directory
UPLD_DIR = os.path.join(Kensa_HOME, 'uploads/')
# Database Directory
DB_DIR = os.path.join(Kensa_HOME, 'db.sqlite3')
# Signatures used by modules
SIGNATURE_DIR = os.path.join(Kensa_HOME, 'signatures/')
# Tools Directory
TOOLS_DIR = os.path.join(BASE_DIR, 'DynamicAnalyzer/tools/')
# Secret File
SECRET_FILE = os.path.join(Kensa_HOME, 'secret')

# Database
# Postgres DB - Install psycopg2
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'kensa',
        'USER': 'kensa',
        'PASSWORD': 'kensa',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
# End Postgres support

# ===============================================

# ==========LOAD CONFIG FROM Kensa HOME==========
try:
    # Update Config from Kensa Home Directory
    if USE_HOME:
        USER_CONFIG = os.path.join(Kensa_HOME, 'config.py')
        sett = imp.load_source('user_settings', USER_CONFIG)
        locals().update(
            {k: v for k, v in list(sett.__dict__.items())
                if not k.startswith('__')})
        CONFIG_HOME = True
    else:
        CONFIG_HOME = False
except Exception:
    logger.exception('Reading Config')
    CONFIG_HOME = False
# ===============================================

# ===KENSA SECRET GENERATION AND DB MIGRATION====
SECRET_KEY = first_run(SECRET_FILE, BASE_DIR, Kensa_HOME)

# =============================================

# =============ALLOWED DOWNLOAD EXTENSIONS=====
ALLOWED_EXTENSIONS = {
    '.txt': 'text/plain',
    '.png': 'image/png',
    '.zip': 'application/zip',
    '.tar': 'application/x-tar',
    '.apk': 'application/octet-stream',
}
# ===============================================

# =============ALLOWED MIMETYPES=================

APK_MIME = [
    'application/octet-stream',
    'application/vnd.android.package-archive',
    'application/x-zip-compressed',
    'binary/octet-stream',
]
IPA_MIME = [
    'application/iphone',
    'application/octet-stream',
    'application/x-itunes-ipa',
    'application/x-zip-compressed',
    'binary/octet-stream',
]
ZIP_MIME = [
    'application/zip',
    'application/octet-stream',
    'application/x-zip-compressed',
    'binary/octet-stream',
]
APPX_MIME = [
    'application/octet-stream',
    'application/vns.ms-appx',
    'application/x-zip-compressed',
]

# ===============================================

# ============DJANGO SETTINGS =================
DEBUG = True
DJANGO_LOG_LEVEL = DEBUG
ALLOWED_HOSTS = ['127.0.0.1', 'kensa', '*']
GRAPPELLI_ADMIN_TITLE = "Kensa Admin"
# Application definition
INSTALLED_APPS = (
    'grappelli',
    'django.contrib.admin',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'users',
    #'grappelli.dashboard',

    'StaticAnalyzer',
    'DynamicAnalyzer',
    'Kensa',
    'MalwareAnalyzer',
)
MIDDLEWARE_CLASSES = (

    'whitenoise.middleware.WhiteNoiseMiddleware',
)

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'Kensa.views.api.rest_api_middleware.RestApiAuthMiddleware',
    #'Kensa.LoginRequiredMiddleware',

]
ROOT_URLCONF = 'Kensa.urls'
WSGI_APPLICATION = 'Kensa.wsgi.application'
LANGUAGE_CODE = 'en-us'
TIME_ZONE = os.getenv('TIME_ZONE', 'UTC')
USE_I18N = True
USE_L10N = True
USE_TZ = True
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'DIRS':
            [
                os.path.join(BASE_DIR, 'templates'),
                os.path.join(BASE_DIR, 'templates', 'allauth'),
                os.path.join(BASE_DIR, 'templates', 'admin'),
            ],
        'OPTIONS':
            {
                'context_processors': [
                    # Already defined Django-related contexts here
                    # `allauth` needs this from django
                        'django.template.context_processors.debug',
                        'django.template.context_processors.request',
                        'django.contrib.auth.context_processors.auth',
                        'django.contrib.messages.context_processors.messages',

                    ],
            },
    },
]
AUTHENTICATION_BACKENDS = (
    # Needed to login by username in Django admin, regardless of `allauth`
    'django.contrib.auth.backends.ModelBackend',

    # `allauth` specific authentication methods, such as login by e-mail
    'allauth.account.auth_backends.AuthenticationBackend',
)
AUTH_USER_MODEL = 'users.User'
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_AUTHENTICATION_METHOD = 'email'

SITE_ID = 1
LOGIN_REDIRECT_URL = '/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'uploads')
MEDIA_URL = '/uploads/'
STATIC_URL = '/static/'
# STATIC_ROOT = os.path.join(BASE_DIR, 'static')

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'
# 256MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 268435456

# ===================
# USER CONFIGURATION
# ===================

if CONFIG_HOME:
    logger.info('Loading User config from: %s', USER_CONFIG)
else:
    """
    IMPORTANT
    If 'USE_HOME' is set to True,
    then below user configuration settings are not considered.
    The user configuration will be loaded from
    config.py in Kensa Home directory.
    """
    # ^CONFIG-START^: Do not edit this line
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    #          KENSA USER CONFIGURATIONS
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    # -------------------------
    # STATIC ANALYZER SETTINGS
    # -------------------------

    # ==========ANDROID SKIP CLASSES==========================
    # Common third party classes that will be skipped during static analysis
    SKIP_CLASSES = [
        r'com[\\\/]{1}google[\\\/]{1}',
        r'com[\\\/]{1}android[\\\/]{1}',
        r'android[\\\/]{1}content[\\\/]{1}',
        r'android[\\\/]{1}support[\\\/]{1}',
        r'android[\\\/]{1}arch[\\\/]{1}',
        r'kotlin[\\\/]{1}',
        r'androidx[\\\/]{1}',
        r'okhttp2[\\\/]{1}', r'okhttp3[\\\/]{1}',
        r'com[\\\/]{1}squareup[\\\/]{1}okhttp[\\\/]{1}',
        r'com[\\\/]{1}twitter[\\\/]{1}',
        r'twitter4j[\\\/]{1}',
        r'org[\\\/]{1}apache[\\\/]{1}',
        r'oauth[\\\/]{1}signpost[\\\/]{1}',
        r'org[\\\/]{1}chromium[\\\/]{1}',
        r'com[\\\/]{1}facebook[\\\/]{1}',
        r'org[\\\/]{1}spongycastle[\\\/]{1}',
        r'com[\\\/]{1}amazon[\\\/]{1}identity[\\\/]{1}',
        r'io[\\\/]{1}fabric[\\\/]{1}sdk[\\\/]{1}',
        r'com[\\\/]{1}instabug[\\\/]{1}',
        r'io[\\\/]{1}fabric[\\\/]{1}sdk[\\\/]{1}',
        r'com[\\\/]{1}crashlytics[\\\/]{1}android[\\\/]{1}',
    ]

    # ==============================================

    # ======WINDOWS STATIC ANALYSIS SETTINGS ===========

    # Private key
    WINDOWS_VM_SECRET = 'Kensa/windows_vm_priv_key.asc'
    # IP and Port of the Kensa Windows VM
    # example: WINDOWS_VM_IP = '127.0.0.1'   ;noqa E800
    WINDOWS_VM_IP = None
    WINDOWS_VM_PORT = '8000'
    # ==================================================

    # ==============3rd Party Tools=================
    """
    If you want to use a different version of 3rd party tools used by Kensa.
    You can do that by specifying the path here. If specified, Kensa will run
    the tool from this location.
    """

    # Android 3P Tools
    JADX_BINARY = ''
    BACKSMALI_BINARY = ''
    APKTOOL_BINARY = ''
    ADB_BINARY = '/home/cloudsigma/Android/Sdk/platform-tools/adb'

    # iOS 3P Tools
    OTOOL_BINARY = ''
    JTOOL_BINARY = ''
    CLASSDUMP_BINARY = ''
    CLASSDUMP_SWIFT_BINARY = ''

    # COMMON
    JAVA_DIRECTORY = ''
    VBOXMANAGE_BINARY = ''
    PYTHON3_PATH = ''

    """
    Examples:
    JAVA_DIRECTORY = 'C:/Program Files/Java/jdk1.7.0_17/bin/'
    JAVA_DIRECTORY = '/usr/bin/'
    VBOXMANAGE_BINARY = '/usr/bin/VBoxManage'
    PYTHON3_PATH = 'C:/Users/Ajin/AppData/Local/Programs/Python/Python35-32/'
    JADX_BINARY = 'C:/Users/Ajin/AppData/Local/Programs/jadx/bin/jadx.bat'
    JADX_BINARY = '/Users/ajin/jadx/bin/jadx'
    """
    # ==========================================================
    # -------------------------
    # DYNAMIC ANALYZER SETTINGS
    # -------------------------

    # =======ANDROID DYNAMIC ANALYSIS SETTINGS===========
    ANALYZER_IDENTIFIER = ''
    FRIDA_TIMEOUT = 4
    # ==============================================

    # ================HTTPS PROXY ===============
    PROXY_IP = '127.0.0.1'
    PROXY_PORT = 1337  # Proxy Port
    # ===================================================

    # ========UPSTREAM PROXY SETTINGS ==============
    # If you are behind a Proxy
    UPSTREAM_PROXY_ENABLED = False
    UPSTREAM_PROXY_SSL_VERIFY = True
    UPSTREAM_PROXY_TYPE = 'http'
    UPSTREAM_PROXY_IP = '127.0.0.1'
    UPSTREAM_PROXY_PORT = 3128
    UPSTREAM_PROXY_USERNAME = ''
    UPSTREAM_PROXY_PASSWORD = ''
    # ==============================================

    # --------------------------
    # MALWARE ANALYZER SETTINGS
    # --------------------------
    DOMAIN_MALWARE_SCAN = True
    APKID_ENABLED = True
    # ==============================================

    # -----External URLS--------------------------
    MALWARE_DB_URL = 'http://www.malwaredomainlist.com/mdlcsv.php'
    VIRUS_TOTAL_BASE_URL = 'https://www.virustotal.com/vtapi/v2/file/'
    EXODUS_URL = 'https://reports.exodus-privacy.eu.org'
    APPMONSTA_URL = 'https://api.appmonsta.com/v1/stores/android/details/'
    ITUNES_URL = 'https://itunes.apple.com/lookup'
    GITHUB_URL = ('https://raw.githubusercontent.com/'
                  'Kensa/'
                  'master/Kensa/settings.py')
    GOOGLE = 'https://www.google.com'
    BAIDU = 'https://www.baidu.com/'

    # -------External -----------------------------
    # Get AppMonsta API from https://appmonsta.com/dashboard/get_api_key/
    APPMONSTA_API = ''

    # ========DISABLED COMPONENTS===================

    # ----------VirusTotal--------------------------
    VT_ENABLED = False
    VT_API_KEY = ''
    VT_UPLOAD = False
    # Before setting VT_ENABLED to True,
    # Make sure VT_API_KEY is set to your VirusTotal API key
    # register at: https://www.virustotal.com/#/join-us
    # You can get your API KEY from:
    # https://www.virustotal.com/en/user/<username>/apikey/
    # Files will be uploaded to VirusTotal
    # if VT_UPLOAD is set to True.
    # ==============================================
    # ^CONFIG-END^: Do not edit this line


# ============JAVA SETTINGS======================
JAVA_BINARY = find_java_binary()
# ===============================================

# Better logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'standard': {
            'format': '[%(levelname)s] %(asctime)-15s - %(message)s',
            'datefmt': '%d/%b/%Y %H:%M:%S',
        },
        'color': {
            '()': 'colorlog.ColoredFormatter',
            'format':
                '%(log_color)s[%(levelname)s] %(asctime)-15s - %(message)s',
            'datefmt': '%d/%b/%Y %H:%M:%S',
            'log_colors': {
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
        },
    },
    'handlers': {
        'logfile': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(Kensa_HOME, 'logs', 'debug.log'),
            'formatter': 'standard',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'color',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'django.db.backends': {
            'handlers': ['console', 'logfile'],
            # DEBUG will log all queries, so change it to WARNING.
            'level': 'INFO',
            'propagate': False,   # Don't propagate to other handlers
        },
        'Kensa': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'StaticAnalyzer': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'MalwareAnalyzer': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'DynamicAnalyzer': {
            'handlers': ['console', 'logfile'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
