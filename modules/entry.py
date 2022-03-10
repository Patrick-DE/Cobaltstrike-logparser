import os, re
from modules.sql.sqlite_func import *

from modules.utils import is_ip_in_ranges
import config

def get_pattern(file):
    """Returns the pattern based on the filepath provided.
    The following pattern are available:
    - beacon_xxx.log : pattern_line
    - downloads.log : pattern_download
    - events.log : pattern_events"""
    fn = os.path.basename(file)
    if "downloads" in fn:
        return "download", config.pattern_download
    elif "events" in fn:
        return "events", config.pattern_events
    else:
        log(f"get_pattern() Failed: No pattern found", "e")
        exit(1)


def redact(content: String) -> String:
    """This function replaces the following entry.content with [REDACTED] in the DB:
    - NTLM hashes, based on regex
    - logonpasswords
    - [-](password|pass|p|pkv)[\s|=|:]
    - (NTLM|SHA1) :
    """
    r = r"\1[REDACTED]"
    # password=, pass=, pvk=, -p:
    content = re.sub(r"((?:\/|-+|\s)(?:p|pass|password|pvk)\s*(?:=|\s|:)\s*)\S+", r, content, re.I)
    # NTLM : , SHA1 : 
    content = re.sub(r"((?:NTLM|SHA1)\s+:\s)\b\w+\b", r, content, re.I)
    # logonpasswords
    content = re.sub(r"(\w+:\d+:)\w+:\w+:::", r, content)
    # /aes265:, /rc4:, /statekey:
    content = re.sub(r"(.*\/(?:aes256|rc4|statekey|ticket)\s*(?:=|:)\s*)(.*?)\s*$", r, content, re.I)
    # make_token
    content = re.sub(r"(make_token .*\s)(.*)", r, content, re.I)
    # ntlm
    content = re.sub(r"^(\\$NT\\$)?[a-f0-9]{32}$", r, content)
    # redact strings which have 32bites or 64 like aes265
    content = re.sub(r"\b([A-Fa-f0-9]{64}|[A-Fa-f0-9]{32})\b", r, content)
    # redact runas [/user:]<user> <pw> <executable>
    content = re.sub(r"(runas.*(\/user:)*\b\w+\b\s+)\S+", r, content)
    # redact creating new user "net user nviso PW /add"
    content = re.sub(r"(net\suser\s\b\w+\b\s)(.*?)\s", r, content)
    return content


def excel_save(content: String) -> String:
    """Replaces the csv seperator ',' with ';'"""
    if "," in content:
        content.replace(",", ";")
    return content

