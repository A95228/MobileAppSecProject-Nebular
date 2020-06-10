# Tools for rest_api.py


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




