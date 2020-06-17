import datetime
import logging
import json
import pdb
import warnings

from django.db import models
from django.core.exceptions import ObjectDoesNotExist
from django.core.paginator import EmptyPage, Paginator, PageNotAnInteger

from StaticAnalyzer.mixins import StaticAnalizerMixin
from StaticAnalyzer.views.rules_properties import (
    Level,
)
from users.models import User

logger = logging.getLogger(__name__)



def score(findings):
    """ Importing scores from its home causes 
    circular imports, placing a copy here."""
    cvss_scores = []
    avg_cvss = 0
    app_score = 100
    for _, finding in findings.items():
        if 'cvss' in finding:
            if finding['cvss'] != 0:
                cvss_scores.append(finding['cvss'])
        if finding['level'] == Level.high.value:
            app_score = app_score - 15
        elif finding['level'] == Level.warning.value:
            app_score = app_score - 10
        elif finding['level'] == Level.good.value:
            app_score = app_score + 5
    if cvss_scores:
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1)
    if app_score < 0:
        app_score = 10
    elif app_score > 100:
        app_score = 100
    return avg_cvss, app_score


class RecentScansDB(models.Model):

    FILE_NAME = models.CharField(max_length=260)
    MD5 = models.CharField(max_length=32)
    URL = models.URLField()
    TIMESTAMP = models.DateTimeField()
    APP_NAME = models.CharField(max_length=260)
    PACKAGE_NAME = models.CharField(max_length=260)
    VERSION_NAME = models.CharField(max_length=50)
    ORGANIZATION_ID = models.CharField(max_length=254)


    @classmethod
    def get_recent_scans(cls, organization_id):
        """
        This method will

        Scan object contains the following keys and values

            image_link: string;
            app_name            ~> string
            file_name           ~> string
            system              ~> string
            timestamp           ~> string
            timestamp_formated  ~> string
            md5                 ~> string
            package_name        ~> string
            version_name        ~> string
            cvss_score          ~> number
            total_issues        ~> number
            issue_high          ~> number
            issue_medium        ~> number
            issue_low           ~> number
            security_score      ~> number
            tracekrs_detection  ~> number
            status              ~> string

        """
        scans = [
            StaticAnalyzerAndroid.objects.filter(
                    ORGANIZATION=organization_id).order_by(
                "-DATE"
            ),
            StaticAnalyzerIOS.objects.filter(
                    ORGANIZATION=organization_id).order_by(
                "-DATE"
            ),
        ]
        rs = []
        for queryset in scans:
            if queryset.count() == 0: continue # don't bother.
            for _ in queryset:
                try:
                    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    # CASE ANDROID
                    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    if isinstance(_, StaticAnalyzerAndroid):
                        scan = StaticAnalyzerAndroid.get_scan_info_from_obj(_)
                        try:
                            ts = eval(_.TRACKERS)
                            tt = ts["total_trackers"]
                            dt = ts['detected_trackers']
                        except:
                            tt = dt = "No trackers"
                        
                        scan["trackers_detected"] =  "%s/%s" % (dt, tt) 

                        try:
                            acvss, sskor = score(eval(_.CODE_ANALYSIS))
                        except Exception as _exe_:
                            logger.exception(_exe_)
                            acvss = sskor = "-"

                        scan["security_score"] = sskor
                        scan["cvss_score"] = acvss

                        try:
                            issues = StaticAnalyzerAndroid.get_total_issue(
                                organization, _.MD5)
                        except Exception as _exe_:
                            logger.exception(_exe_)
                            issues = ""
                        scan["issues"] =  issues

                    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    # CASE IOS
                    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    else:
                        scan = StaticAnalyzerIOS.get_scan_info_from_obj(_)
                        try:
                            acvss, sskor = score(eval(_.CODE_ANALYSIS))
                        except Exception as _exe_:
                            logger.exception(_exe_)
                            acvss = sskor = "-"

                        scan["security_score"] = sskor
                        scan["cvss_score"] = acvss

                        try:
                            issues = StaticAnalyzerIOS.get_total_issue(_.MD5)
                        except Exception as _exe_:
                            logger.exception(str(_exe_))
                            issues = ""
                        scan["issues"] = issues

                except Exception as _exe_:
                    logger.exception(str(_exe_))
                    rs.append({})
                    continue
            
                rs.append(scan)

        return rs
    
    @classmethod
    def get_fresh_up_save(cls, *args):
        """Get a recent scan or update first arg 
        needs to be organization, second md5."""
        for fresh in cls.get_recent_scans(args[0]):
            if 'app_info' in fresh:
                if fresh["app_info"]["md5"] == args[1]:
                    return fresh
        return None


class StaticAnalyzerAndroid(models.Model, StaticAnalizerMixin):
    # Relational Fields
    USER = models.ForeignKey(User, on_delete=models.CASCADE)
    ORGANIZATION = models.CharField(max_length=254)
    # Informational Fields
    DATE = models.DateField(
        auto_now=True, auto_created=True, verbose_name="date_when_created"
    )
    FILE_NAME = models.CharField(max_length=260)
    APP_NAME = models.CharField(max_length=255)
    APP_TYPE = models.CharField(max_length=20, default="")
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


    @staticmethod
    def paginate(load, page, count=30):
        """Paginate a context"""
        try:
            if "trackers" in load:
                paginator = Paginator(load["trackers"], count)
            elif "scans" in load:
                paginator = Paginator(load["scans"], count)
            else:
                paginator = Paginator(load, count)
            activities = paginator.page(page)
        except PageNotAnInteger:
            activities = paginator.page(1)
        except EmptyPage:
            activities = paginator.page(paginator.num_pages)
        except Exception as e:
            return None

        resp = {
            "page": activities.number,
            "total_pages": paginator.num_pages,
            "limit": 30,
            "list": activities.object_list,
        }
        return resp
    
    @classmethod
    def get_scan_info_from_obj(cls, scan_obj):
        try:
            if scan_obj.ICON_FOUND:
                icon_url = "/download/{0}-icon.png".format(scan_obj.MD5)
            else:
                icon_url = "img/no_icon.png"

            try:
                ca = scan_obj.CERTIFICATE_ANALYSIS
                try:
                    ca = eval(ca)
                    cert_stat = ca["certificate_status"]
                except KeyError:
                    cert_stat = ""
                except TypeError:
                    cert_stat = ca
                except:
                    cert_stat = ""
                cert_stat = "bad" if cert_stat == "warning" else "good"
            except:
                cert_stat = ""

            scan_info = {
                "icon_url": icon_url,
                "file_name": scan_obj.FILE_NAME,
                "system": "android",
                "date": scan_obj.DATE.__format__("%b, %d, %Y"),
                "certificate_status": cert_stat,
                "app_info": {
                    "file_name": scan_obj.FILE_NAME,
                    "size": scan_obj.SIZE,
                    "md5": scan_obj.MD5,
                    "sha1": scan_obj.SHA1,
                    "sha256": scan_obj.SHA256,
                    "app_name": scan_obj.APP_NAME,
                    "package_name": scan_obj.PACKAGE_NAME,
                    "main_activity": scan_obj.MAIN_ACTIVITY,
                    "target_sdk": scan_obj.TARGET_SDK,
                    "max_sdk": scan_obj.MAX_SDK,
                    "min_sdk": scan_obj.MIN_SDK,
                    "version_name": scan_obj.VERSION_NAME,
                    "version_code": scan_obj.VERSION_CODE,
                },
            }
            return scan_info
        except Exception as error:
            return None
    
    @classmethod
    def get_certificate_analysis_data(cls, organization, md5):
        """Get a certificate return None otherwise.
        Requires no pagination."""
        logger.info("Getting certificate analysis of %s" % md5)
        try:
            cert = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            cert = cert.CERTIFICATE_ANALYSIS
        except:
            logger.error("ObjectNotFound with md5 %s" % md5)
            return None
        return eval(cert)

    @classmethod
    def get_manifest(cls, organization, md5):
        """Get a manifest return None otherwise.
        Requires no pagination."""
        logger.info("Getting manifest data of %s" % md5)
        try:
            cert = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            manifest = cert.MANIFEST_ANALYSIS
        except:
            logger.error("ObjectNotFound with md5 %s" % md5)
            return None
        manifest = dict(manifest_analysis=eval(manifest))
        return manifest

    @classmethod
    def get_recon_trackers(cls, organization, md5, page):
        """Get reconnaisance trackers, or return None.
        Requires pagination."""
        logger.info("Getting reconnassaince trackers of %s" % md5)
        try:
            query = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            trackers = eval(query.TRACKERS)
        except (cls.DoesNotExist, ObjectDoesNotExist):
            logger.error("Object %s does not exists")
            return None
        except Exception:
            logger.error("Unexpected error geting recon trackers of %s" % md5)
            return None
        return {"trackers": cls.paginate(trackers, page)}

    @classmethod
    def get_app_info(cls, organization, md5):
        logger.info("get_app_info of %s" % md5)
        try:
            db_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            app_info = {
                "file_name": db_entry.FILE_NAME,
                "size": db_entry.SIZE,
                "md5": db_entry.MD5,
                "sha1": db_entry.SHA1,
                "sha256": db_entry.SHA256,
                "app_name": db_entry.APP_NAME,
                "package_name": db_entry.PACKAGE_NAME,
                "main_activity": db_entry.MAIN_ACTIVITY,
                "target_sdk": db_entry.TARGET_SDK,
                "max_sdk": db_entry.MAX_SDK,
                "min_sdk": db_entry.MIN_SDK,
                "version_name": db_entry.VERSION_NAME,
                "version_code": db_entry.VERSION_CODE,
            }
            return app_info
        except:
            logger.info("error get_app_info of %s" % md5)
            return None

    @classmethod
    def get_app_store(cls, organization, md5):
        """Get's application store information, or
        returns None."""
        try:
            logger.info("get_app_store of %s" % md5)
            db_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            app_store_info = eval(db_entry.PLAYSTORE_DETAILS)
            return app_store_info
        except:
            logger.info("error get_app_store of %s" % md5)
            return None

    @classmethod
    def get_security_overview(cls, organization, md5):
        """Generates a security overview context, 
        or returns None."""
        try:
            logger.info("get_security_overview of %s" % md5)
            db_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            mani_high = mani_medium = mani_info = 0
            manifest = eval(db_entry.MANIFEST_ANALYSIS)
            for item in manifest:
                if item["stat"] == "high":
                    mani_high = mani_high + 1
                elif item["stat"] == "medium":
                    mani_medium = mani_medium + 1
                elif item["stat"] == "info":
                    mani_info = mani_info + 1
            code_high = code_good = code_warning = code_info = 0
            code_analysis = eval(db_entry.CODE_ANALYSIS)
            if code_analysis and "items" in code_analysis.keys():
                for _, details in code_analysis["items"]:
                    if details["level"] == "high":
                        code_high = code_high + 1
                    elif details["level"] == "good":
                        code_good = code_good + 1
                    elif details["level"] == "warning":
                        code_warning = code_warning + 1
                    elif details["level"] == "info":
                        code_info = code_info + 1
            binary_high = binary_medium = binary_info = 0
            binary = eval(db_entry.BINARY_ANALYSIS)
            for item in binary:
                if item["stat"] == "high":
                    binary_high = binary_high + 1
                elif item["stat"] == "medium":
                    binary_medium = binary_medium + 1
                elif item["stat"] == "info":
                    binary_info = binary_info + 1

            security_overview = {
                "manifest": {
                    "high": mani_high,
                    "medium": mani_medium,
                    "info": mani_info,
                },
                "code": {
                    "high": code_high,
                    "good": code_good,
                    "warning": code_warning,
                    "info": code_info,
                },
                "binary": {
                    "high": binary_high,
                    "medium": binary_medium,
                    "info": binary_info,
                },
            }

            return security_overview
        except:
            logger.info("error get_security_overview of %s" % md5)
            return None

    @classmethod
    def get_components_activities(cls, organization, md5):
        logger.info("get_components_activities of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            activities = eval(data_entry.ACTIVITIES)
        except:
            logger.info("get_components_activities error %s" % md5)
            return None
        return activities

    @classmethod
    def get_apkid_analysis(cls, organization, md5):
        logger.info("get_apkid_analysis of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            apkid = eval(data_entry.APKID)
        except:
            logger.info("get_apkid_analysis error %s" % md5)
            return None
        return apkid

    @classmethod
    def get_components_services(cls, organization, md5):
        logger.info("get_components_servicees of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            services = eval(data_entry.SERVICES)
        except:
            logger.info("get_components_servicees error %s" % md5)
            return None
        return services

    @classmethod
    def get_components_receivers(cls, organization, md5):
        logger.info("get_components_receivers of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            receivers = data_entry.RECEIVERS
        except:
            logger.info("get_components_receivers error %s" % md5)
            return None
        return receivers

    @classmethod
    def get_components_providers(cls, organization, md5):
        logger.info("get_components_providers of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            providers = data_entry.PROVIDERS
        except:
            logger.info("get_components_providers error %s" % md5)
            return None
        return providers

    @classmethod
    def get_manifest_analysis(cls, organization, md5):
        logger.info("get_components_files of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            manifest = eval(data_entry.MANIFEST_ANALYSIS)
            count_high = count_info = count_medium = 0
            manifest_response = []
            for i in range(len(manifest)):
                if manifest[i]["stat"] == "high":
                    count_high = count_high + 1
                elif manifest[i]["stat"] == "medium":
                    count_medium = count_medium + 1
                elif manifest[i]["stat"] == "info":
                    count_info = count_info + 1
                manifest_response.append(
                    {
                        "severity": manifest[i]["stat"],
                        "issue": manifest[i]["title"],
                        "description": manifest[i]["desc"],
                    }
                )
            return {
                "count": {
                    "high": count_high,
                    "medium": count_medium,
                    "info": count_info,
                },
                "list": manifest_response,
            }
        except:
            logger.info("get_components_files error %s" % md5)
            return None

    @classmethod
    def get_total_issue(cls, organization, md5):
        obj = cls.get_single_or_none(organization, md5=md5)
        if obj is None:
            return None
        # issue from shard library
        issue_binary = len(obj.BINARY_ANALYSIS)
        # issue from manifest
        issue_manifest = len(obj.MANIFEST_ANALYSIS)
        # issue from code_analysis
        code_analysis = eval(obj.CODE_ANALYSIS)
        issue_code_analysis = 0
        if "items" in code_analysis.keys():
            issue_code_analysis = len(code_analysis["items"])
        file_analysis = eval(obj.FILE_ANALYSIS)
        issue_file_analysis = len(file_analysis)
        total_issue = issue_binary + issue_manifest + issue_code_analysis + issue_file_analysis
        return total_issue

    @classmethod
    def get_app_permissions(cls, organization, md5):
        logger.info("get_app_permissions of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            permissions = eval(data_entry.PERMISSIONS)
            permissions_list = []
            for key, value in permissions.items():
                temp = {key: value}
                permissions_list.append(temp)
            return permissions_list
        except:
            logger.info("get_app_permissions error %s" % md5)
            return None


class StaticAnalyzerIOS(models.Model, StaticAnalizerMixin):
    """This model represents the information obtained from a scan operation."""

    USER = models.ForeignKey(User, on_delete=models.CASCADE)
    ORGANIZATION = models.CharField(max_length=254)
    DATE = models.DateField(
        auto_now=True, auto_created=True, verbose_name="date_when_created"
    )
    FILE_NAME = models.CharField(max_length=255)
    APP_NAME = models.CharField(max_length=255)
    APP_TYPE = models.CharField(max_length=20, default="")
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

    @staticmethod
    def paginate(load, page, count=30):
        """Paginate a context"""
        try:
            paginator = Paginator(load, count)
            activities = paginator.page(page)
        except PageNotAnInteger:
            activities = paginator.page(1)
        except EmptyPage:
            activities = paginator.page(paginator.num_pages)
        except:
            return None

        resp = {
            "page": activities.number,
            "total_pages": paginator.num_pages,
            "limit": 30,
            "list": activities.object_list,
        }
        return resp

    @classmethod
    def get_app_info(cls, organization, md5):
        """Get's application information, or returns None."""
        logger.info("ios get_app_info of %s" % md5)
        try:
            db_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            app_info = {
                "file_name": db_entry.FILE_NAME,
                "size": db_entry.SIZE,
                "md5": db_entry.MD5,
                "sha1": db_entry.SHA1,
                "sha256": db_entry.SHA256,
                "app_name": db_entry.APP_NAME,
                "app_type": db_entry.APP_TYPE,
                "identifier": db_entry.BUNDLE_ID,
                "version": db_entry.APP_VERSION,
                "build": db_entry.BUILD,
                "platform": db_entry.PLATFORM,
                "min_os_version": db_entry.MIN_OS_VERSION,
                "supported_platform": eval(db_entry.BUNDLE_SUPPORTED_PLATFORMS),
            }
            return app_info
        except:
            logger.info("error get_app_info %s" % md5)
            return None

    @classmethod
    def get_scan_info_from_obj(cls, scan_obj):
        try:
            if scan_obj.ICON_FOUND:
                icon_url = "/download/{0}-icon.png".format(scan_obj.MD5)
            else:
                icon_url = "img/no_icon.png"
            scan_info = {
                "file_name": scan_obj.FILE_NAME,
                "icon_url": icon_url,
                "date": scan_obj.DATE.__format__("%b, %d, %Y"),
                "app_info": cls.get_app_info(scan_obj.ORGANIZATION, scan_obj.MD5),
            }
            return scan_info
        except:
            return None

    @classmethod
    def get_app_store(cls, organization, md5):
        """Gets application store information, or returns None."""
        try:
            logger.info("get_app_store of %s" % md5)
            db_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            app_stor_info = eval(db_entry.APPSTORE_DETAILS)
            return app_stor_info
        except:
            logger.info("error get_app_store of %s" % md5)
            return None

    @classmethod
    def get_app_permissions(cls, organization, md5):
        """Get's applications permissions or returns None."""
        logger.info("get_app_permissions of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            permissions = eval(data_entry.PERMISSIONS)
            return permissions
        except:
            logger.info("get_app_permissions error %s" % md5)
            return None

    @classmethod
    def get_libraries(cls, organization, md5):
        logger.info("get_libraries of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            permissions = eval(data_entry.PERMISSIONS)
            return permissions
        except:
            logger.info("get_libraries error %s" % md5)
            return None

    @classmethod
    def get_security_overview(cls, organization, md5):
        """Gets security overview, or returns None."""
        try:
            logger.info("get_security_overview of %s" % md5)
            db_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)

            ats_secure = ats_insecure = ats_warning = ats_info = 0
            ats = eval(db_entry.ATS_ANALYSIS)
            for item in ats:
                if item["status"] == "secure":
                    ats_secure = ats_secure + 1
                elif item["status"] == "insecure":
                    ats_insecure = ats_insecure + 1
                elif item["status"] == "warning":
                    ats_warning = ats_warning + 1
                elif item["status"] == "info":
                    ats_info = ats_info + 1
            binary_high = binary_good = binary_warning = binary_info = 0
            bns = eval(db_entry.BINARY_ANALYSIS)
            for key in bns:
                details = bns[key]
                if details["level"] == "high":
                    binary_high = binary_high + 1
                elif details["level"] == "good":
                    binary_good = binary_good + 1
                elif details["level"] == "warning":
                    binary_warning = binary_warning + 1
                elif details["level"] == "info":
                    binary_info = binary_info + 1

            security_overview = {
                "ats": {
                    "secure": ats_secure,
                    "insecure": ats_insecure,
                    "warning": ats_warning,
                    "info": ats_info,
                },
                "binary": {
                    "high": binary_high,
                    "secure": binary_good,
                    "warning": binary_warning,
                    "info": binary_info,
                },
            }
            return security_overview
        except:
            logger.info("error get_security_overview of %s" % md5)
            return None

    @classmethod
    def get_total_issue(cls, organization, md5):
        obj = cls.get_single_or_none(ORGANIZATION=organization, md5=md5)
        if obj is None:
            return None
        # issue from shard library
        issue_binary = len(obj.BINARY_ANALYSIS)
        # issue from code_analysis
        code_analysis = eval(obj.CODE_ANALYSIS)
        issue_code_analysis = 0
        if "items" in code_analysis.keys():
            issue_code_analysis = len(code_analysis["items"])
        file_analysis = eval(obj.FILE_ANALYSIS)
        issue_file_analysis = len(file_analysis)
        total_issue = issue_binary + issue_code_analysis + issue_file_analysis
        return total_issue


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
