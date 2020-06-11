# Tools for rest_api.py

import re


BAD_REQUEST = 400
BAD_REQUEST = 400
OK = 200
NOT_FOUND = 404
SYSTEMS = [
    "android", "ios"
]

SYSTEMS_DROP = "Systems allowed: %s" % ", ".join(SYSTEMS)


def merge_searches(*args):
    """Helper for search route."""
    i = []
    for value_list in args:
        for value in value_list:
            try:
                i.append(value["MD5"])
            except KeyError:
                continue
    return i


def request_check(request):
    """ """
    if request.GET.get("md5", None) is None:
        return False, {"error" : "Missing md5 param"}, BAD_REQUEST
    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return False, {"error" : "Invalid md5"}, BAD_REQUEST
    return True, OK


def system_check(request):
    """Check systems parameter"""
    if request.GET.get("system", None) is None:
        return False, {"error" : "missing system type"}, BAD_REQUEST
    if not request.GET.get("system").lower() in SYSTEMS:
        return False, {"error" : SYSTEMS_DROP}, BAD_REQUEST
    return True, OK


def get_page(request):
    """Get page from request, if view enables pagination"""
    if request.GET.get("page", None) is not None:
        if re.match(r"^\d+$", request.GET["page"]):
            return request.GET["page"]
        else:
            return 1
    else:
        return 1



