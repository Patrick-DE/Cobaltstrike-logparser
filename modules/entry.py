import os, re
from modules.sql.sqlite_func import *
from modules.configuration import get_config

def get_pattern(file):
    """Returns the pattern based on the filepath provided.
    The following pattern are available:
    - beacon_xxx.log : pattern_line
    - downloads.log : pattern_download
    - events.log : pattern_events"""
    config = get_config()
    
    fn = os.path.basename(file)
    if "downloads" in fn:
        return "download", config.parsing.cs.download
    elif "events" in fn:
        return "events", config.parsing.cs.events
    else:
        log(f"get_pattern() Failed: No pattern found", "e")
        exit(1)


def redact(content: str) -> str:
    """
    Redact sensitive information based on global config
    Args:
        content: String to redact
    Returns:
        Redacted content string
    """
    config = get_config()
    
    replacement = config.redactions.flags.replacement
    case_insensitive = config.redactions.flags.case_insensitive
    
    # Apply each pattern
    for name, pattern_config in config.redactions.patterns.items():
        regex_flags = re.I if case_insensitive else 0
        try:
            content = re.sub(
                pattern_config.pattern.strip(),
                replacement,
                content,
                flags=regex_flags
            )
        except re.error as e:
            log(f"Redaction failed for pattern {name}: {e}", "e")
    
    return content


def excel_save(content: String) -> String:
    """Replaces the csv seperator ',' with ';'"""
    if "," in content:
        content.replace(",", ";")
    return content
