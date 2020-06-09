import logging 
import os
import re
import subprocess

from django.conf import settings
from django.utils.html import escape


logger = logging.getLogger(__name__)



def get_smali_drop(md5):
    """Get smali code"""
    if subprocess.run(["which", "find"], capture_output=True).returncode != 0:
        logger.error("Can't find 'find' command, contact sysadmin")
        return None
    try:
        tgt = os.path.join(settings.UPLD_DIR, md5, "smali_source")
    except AttributeError as error:
        logger.error(str(error))
        return None
    logger.info("Running subprocess for smali file search of scan %s" % md5)
    runner = subprocess.run(
            ["find", tgt, "-regex", ".*\.smali$"],
            capture_output=True)
    if runner.returncode != 0:
        msg = "find command returned %s for .smali files search of %s" % (
            runner.returncode, md5)
        logger.error(msg)
    logger.info("find command search OK for scan %s" % md5)
    drop = runner.stdout.decode('utf-8').split("\n")
    if drop.__len__() == 0:
        logger.info("No .smali files for  scan %s" % md5)
    files = []
    for each in drop:
        match = re.match(r'.+\/smali_source\/(?P<path>.+\.smali)$', each)
        if not match:
            continue
        this = match.group("path")
        if not this.endswith(".smali"):
            continue
        files.append(escape(this))
    context = {
        'title': 'Smali Source',
        'files': sorted(files),
        '_type': 'apk',
        '_hash': md5,
        'version': settings.KENSA_VER,
    }
    logger.info("Fetching %s smali files for scan %s" % (len(drop), md5))
    return context 
    


