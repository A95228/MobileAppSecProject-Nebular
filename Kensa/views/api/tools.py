# Tools for rest_api.py

BAD_REQUEST = 400
OK = 200
NOT_FOUND = 404

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


def halt_check(request):
    
    if request.GET.get("md5", None) is None:
        return False, {"error" : "Mr"}, BAD_REQUEST

    if not re.match(r"^[0-9a-f]{32}$", request.GET["md5"]):
        return False, {"error" : "Invalid md5"}, BAD_REQUEST




