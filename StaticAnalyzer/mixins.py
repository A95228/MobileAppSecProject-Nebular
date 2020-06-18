"""
Logic reducer object
~~~~~~~~~~~~~~~~~~~~
"""

import logging

from django.core.exceptions import ObjectDoesNotExist


logger = logging.getLogger(__name__)


class StaticAnalizerMixin(object):
    """StaticAnalizerMixin class"""

    @classmethod
    def get_org_user(cls, md5):
        logger.info("get_org_user of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            org_id = data_entry.ORGANIZATION
            user = data_entry.USER
            return org_id, user
        except:
            logger.info("get_app_permissions error %s" % md5)
            return None, None

    @classmethod
    def cook_scan(cls, **kwargs):
        """Scan Factory"""
        if "USER" not in kwargs:
            return False
        if "ORGANIZATION" not in kwargs:
            return False
        cls.objects.create(**kwargs)
        return True

    @classmethod
    def get_single_or_none(cls, organization, md5):
        """Get a single model or None"""
        try:
            return cls.objects.get(ORGANIZATION=organization, MD5=md5)
        except (cls.DoesNotExist, ObjectDoesNotExist):
            return None

    @classmethod
    def get_md5s(cls, organization, md5):
        """Get md5 that match the given term for a search result,
        return an empty list otherwise."""
        md5s = (cls.objects
                    .filter(MD5__icontains=md5)
                    .filter(ORGANIZATION__exact=organization)
                    .order_by("-DATE")
                    .values("MD5")
                )
        if md5s.count() == 0:
            return []
        return md5s

    @classmethod
    def get_code_analysis(cls, organization, md5):
        """Gets code analysis, or returns None."""
        logger.info("get_code_analysis of %s" % md5)
        try:
            data_entry = cls.objects.get(MD5=md5)
            code_analysis = eval(data_entry.CODE_ANALYSIS)
            return code_analysis
        except:
            logger.info("get_code_analysis error %s" % md5)
            return None

    @classmethod
    def get_components_files(cls, organization, md5):
        logger.info("get_components_files of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            files = eval(data_entry.FILES)
        except:
            logger.info("get_components_files error %s" % md5)
            return None
        return files

    @classmethod
    def get_components_libraries(cls, organization,  md5):
        logger.info("get_components_libraries of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            libraries = eval(data_entry.LIBRARIES)
        except:
            logger.info("get_components_libraries error %s" % md5)
            return None
        return libraries

    @classmethod
    def get_file_analysis(cls, organization, md5):
        logger.info("get_file_analysis of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            file_analysis = eval(data_entry.FILE_ANALYSIS)
            return file_analysis
        except:
            logger.info("get_file_analysis error %s" % md5)
            return None
    
    @classmethod
    def get_scan_info(cls, organization, md5):
        try:
            scan_obj = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            scan_info = cls.get_scan_info_from_obj(scan_obj)
            return scan_info
        except:
            return None

    @classmethod
    def get_recon_emails(cls, organization, md5, page):
        """Get Reconnaissance emails or return None. 
        Requires pagination"""
        logger.info("Getting reconnassaince emails of %s" % md5)
        try:
            query = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            emails = eval(query.EMAILS)
        except (cls.DoesNotExist, ObjectDoesNotExist):
            logger.error("Object %s does not exists" % md5)
            return None
        except Exception:
            logger.error("Error geting reconnaissance emails of %s" % md5)
            return None
        return {"emails": cls.paginate(emails, page)}

    @classmethod
    def get_recon_urls(cls, organization, md5, page):
        """Get reconnaissance urls or None. 
        Requires pagination."""
        logger.info("Getting urls of %s" % md5)
        try:
            query = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            urls = eval(query.URLS)
        except (cls.DoesNotExist, ObjectDoesNotExist):
            logger.error("Object %s does not exists")
            return None
        except Exception:
            logger.error("Unexpected error geting recon urls of %s" % md5)
            return None
        return {"urls": cls.paginate(urls, page)}

    @classmethod
    def get_recon_firebase_db(cls, organization, md5, page):
        """Get reconnaissance firebase url. 
        Requires pagination."""
        logger.info("Getting firebase urls of %s" % md5)
        try:
            query = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            firebase_urls = eval(query.FIREBASE_URLS)
        except (cls.DoesNotExist, ObjectDoesNotExist):
            logger.error("Object %s does not exists")
            return None
        except Exception:
            logger.error("Unexpected error geting fb_db_urls of %s" % md5)
            return None
        return {"firebase_urls": cls.paginate(firebase_urls, page)}

    @classmethod
    def get_recon_strings(cls, organization, md5, page):
        """Get reconnaissance strings, or return None 
        Requires pagination."""
        logger.info("Getting strings of %s" % md5)
        try:
            query = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            strings = eval(query.STRINGS)
        except (cls.DoesNotExist, ObjectDoesNotExist):
            logger.error("Object %s does not exists")
            return None
        except Exception as error:
            logger.error("%s : object -> %s" % (str(error), md5))
            return None
        return {"strings": cls.paginate(strings, page)}

    @classmethod
    def get_domains_data(cls, organization, md5):
        """Get domains"""
        countries = []
        logger.info("Getting domains data of %s" % md5)
        try:
            query = cls.objects.get(ORGANIZATION=organization, MD5=md5)
        except:
            return None
        try:
            domains = eval(query.DOMAINS)
            for key, value in domains.items():
                holder = {}
                geolocation = value.get("geolocation", None)
                if geolocation is None:
                    holder[key] = {}
                    for k in value.keys():
                        if k in ("good", "bad"):
                            holder[key][k] = value.get(k, None)
                    holder[key]["domain"] = key
                    countries.append(holder)
                    continue
                country = geolocation.pop("country_long")
                holder[country] = {}
                holder[country]["domain"] = key
                for k in value.keys():
                    if k in ("good", "bad"):
                        holder[country][k] = value.get(k, None)
                holder[country].update(geolocation)
                countries.append(holder)
        except:
            logger.info("Issue getting domains for object : %s" % md5)
            return None
        return {"countries": countries}

    @classmethod
    def get_domain_analysis(cls, organization, md5):
        logger.info("get_components_files of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            domains = eval(data_entry.DOMAINS)
            bad_country = {}
            for key, value in domains.items():
                bad = value.get("bad", None)
                if bad is None:
                    continue
                geolocation = value.get("geolocation", None)
                if geolocation is None:
                    continue
                country_long = geolocation["country_long"]
                # country_short = geolocation['country_short']
                if country_long in bad_country.keys():
                    bad_country[country_long]["domain"].append(key)
                else:
                    bad_country[country_long] = {"count": 0, "domain": [key]}
                if bad == "yes":
                    bad_country[country_long]["count"] = (
                        bad_country[country_long]["count"] + 1
                    )

            bad_country_list = []
            for key, value in bad_country.items():
                bad_country_list.append(
                    {
                        "count": value["count"],
                        "domains": value["domain"],
                        "country": key,
                    }
                )
            for i in range(len(bad_country_list) - 1):
                for j in range(i + 1, len(bad_country_list)):
                    if bad_country_list[i]["count"] < bad_country_list[j]["count"]:
                        temp = bad_country_list[j]
                        bad_country_list[j] = bad_country_list[i]
                        bad_country_list[i] = temp
            if len(bad_country_list) >= 3:
                return {
                    bad_country_list[0]["country"]: {
                        "bad_count": bad_country_list[0]["count"],
                        "domain": bad_country_list[0]["domains"][0],
                    },
                    bad_country_list[1]["country"]: {
                        "bad_count": bad_country_list[1]["count"],
                        "domain": bad_country_list[1]["domains"][0],
                    },
                    bad_country_list[2]["country"]: {
                        "bad_count": bad_country_list[2]["count"],
                        "domain": bad_country_list[2]["domains"][0],
                    },
                }
            elif len(bad_country_list) == 1:
                return {
                    bad_country_list[0]["country"]: {
                        "bad_count": bad_country_list[0]["count"],
                        "domain": bad_country_list[0]["domains"][:3],
                    },
                }
            elif len(bad_country_list) == 2:
                if len(bad_country_list[0]["domains"]) > 1:
                    return {
                        bad_country_list[0]["country"]: {
                            "bad_count": bad_country_list[0]["count"],
                            "domain": bad_country_list[0]["domains"][:2],
                        },
                        bad_country_list[1]["country"]: {
                            "bad_count": bad_country_list[1]["count"],
                            "domain": bad_country_list[1]["domains"][0],
                        },
                    }
                elif len(bad_country_list[1]["domains"]) > 1:
                    return {
                        bad_country_list[0]["country"]: {
                            "bad_count": bad_country_list[0]["count"],
                            "domain": bad_country_list[0]["domains"][0],
                        },
                        bad_country_list[1]["country"]: {
                            "bad_count": bad_country_list[1]["count"],
                            "domain": bad_country_list[1]["domains"][:2],
                        },
                    }
                else:
                    return {
                        bad_country_list[0]["country"]: {
                            "bad_count": bad_country_list[0]["count"],
                            "domain": bad_country_list[0]["domains"][0],
                        },
                        bad_country_list[1]["country"]: {
                            "bad_count": bad_country_list[1]["count"],
                            "domain": bad_country_list[1]["domains"][0],
                        },
                    }
        except:
            logger.info("get_components_files error %s" % md5)
            return None

    @classmethod
    def get_code_analysis_report(cls, organization, md5):
        """Get's code analysis report, or returns None."""
        logger.info("get_code_analysis of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            code_analysis = eval(data_entry.CODE_ANALYSIS)
            code_high = code_good = code_warning = code_info = 0
            resp_code = []
            for issue, details in code_analysis.items():
                if details["level"] == "high":
                    code_high = code_high + 1
                elif details["level"] == "good":
                    code_good = code_good + 1
                elif details["level"] == "warning":
                    code_warning = code_warning + 1
                elif details["level"] == "info":
                    code_info = code_info + 1
                resp_code.append(
                    {
                        "severity": details["level"],
                        "issue": issue,
                        "description": {
                            "cvss": details["cvss"],
                            "cwe": details["cwe"],
                            "owasp": details["owasp"],
                            "owasp-mstg": details["owasp-mstg"],
                            "path": details["path"],
                        },
                    }
                )
            return {
                "count": {
                    "high": code_high,
                    "good": code_good,
                    "warning": code_warning,
                    "info": code_info,
                },
                "list": resp_code,
            }
        except Exception as error:
            logger.error(str(error))
            logger.info("get_code_analysis error %s" % md5)
            return None

    @classmethod
    def get_binary_analysis(cls, organization, md5):
        """Generates binary analysis or returns None.
        Throws error, needs patch.
        """
        logger.info("get_binary_analysis of %s" % md5)
        try:
            data_entry = cls.objects.get(ORGANIZATION=organization, MD5=md5)
            binary_analysis = eval(data_entry.BINARY_ANALYSIS)
            binary_high = binary_info = binary_medium = 0
            resp_binary = []
            for i in range(0, len(binary_analysis)):
                if binary_analysis[i]["stat"] == "high":
                    binary_high = binary_high + 1
                elif binary_analysis[i]["stat"] == "info":
                    binary_info = binary_info + 1
                elif binary_analysis[i]["stat"] == "medium":
                    binary_medium = binary_medium + 1
                resp_binary.append(
                    {
                        "severity": binary_analysis[i]["stat"],
                        "issue": binary_analysis[i]["title"],
                        "description": binary_analysis[i]["desc"],
                        "files": binary_analysis[i]["file"],
                    }
                )
            return {
                "count": {
                    "high": binary_high,
                    "medium": binary_medium,
                    "info": binary_info,
                },
                "list": resp_binary,
            }
        except:
            logger.info("get_binary_analysis error %s" % md5)
            return None