from datetime import datetime
import re
import os
from typing import List, Tuple

from modules.configuration import config, get_config
from modules.utils import log
from modules.sql.sqlite_model import Entry, EntryType

from modules.beacon import *
from modules.entry import *


# def get_pattern(type: str) -> Tuple[str, str]:
#     """Get pattern based on file type"""
#     config = get_config()
    
#     if type == "beacon":
#         return "line", config.parsing.cs.line
#     elif type == "downloads":
#         return "downloads", config.parsing.cs.download
#     elif type == "events":
#         return "events", config.parsing.cs.events
#     else:
#         log(f"get_pattern() Failed: No pattern found", "e")
#         exit(1)

# def parse_line(line: str, type: str, date: str = None) -> Entry:
#     """Parse a line using the appropriate pattern"""
#     pattern_type, pattern = get_pattern(type)
    
#     entry = re.match(pattern, line)
#     if not entry:
#         return None
        
#     try:
#         timestamp = entry["timestamp"].split(' ')[1]
#         parsed_date = datetime.strptime(f"{date} {timestamp}", "%y%m%d %H:%M:%S") if date else None
        
#         return Entry(
#             timestamp=parsed_date,
#             type=EntryType[pattern_type],
#             content=entry["content"].strip()
#         )
#     except (KeyError, ValueError) as e:
#         log(f"parse_line() Failed: {e}", "e")
#         return None


def parse_beacon_log(file: String) -> None:
    config = get_config()
    
    bid, date = create_beacon_from_file(file)
    if not bid:
        return

    row = {'timestamp': None, 'timezone': None,
           'type': None, 'content': None, "parent_id": bid}
    foundMeta = False
    # parse log entries
    lines = open(file, 'r', encoding="UTF-8").readlines()
    for line in lines:
        matches = re.match(config.parsing.cs.line, line, re.MULTILINE)

        # if line is start of a new log entry process, if not append to content
        if matches != None and len(matches.groups()) == 4:
            # only save if you have all content
            if row['content'] != None:
                create_element(Entry, **row)

            if foundMeta == False and matches["type"] == "metadata":
                metadata = get_beacon_metadata(line, date)
                metadata["id"] = bid
                update_element(Beacon, **metadata)
                foundMeta = True

            row['timestamp'] = datetime.strptime(
                date + " " + matches["timestamp"].split(' ')[1], '%y%m%d %H:%M:%S')
            row['timezone'] = matches["timezone"]
            row['type'] = matches["type"]
            if matches["type"] == "indicator" or "ls" in matches["content"]:
                row['content'] = excel_save(matches["content"])
            else:
                row['content'] = excel_save(redact(matches["content"]))
        elif not matches:
            row['content'] += line
        else:
            log(
                f"parse_beacon_file(): Threw away some information: {line}", "w")


def parse_additional_log(file: String) -> None:
    """Parses the file provided and stores an entry per valid line in the DB"""
    config = get_config()
    
    logtype, pattern = get_pattern(file)
    row = {'timestamp': None, 'timezone': None,
           'type': None, 'content': None, "parent_id": None}

    date = re.findall(config.parsing.cs.date, file, re.MULTILINE)[0]

    # parse log entries
    lines = open(file, 'r', encoding="UTF-8").readlines()
    for line in lines:
        matches = re.match(pattern, line, re.MULTILINE)

        # if line is start of a new log entry process, if not append to content
        # 4 = ?
        # 5 for download
        # 6 for events
        if matches != None and (len(matches.groups()) == 4 or len(matches.groups()) == 5  or len(matches.groups()) == 6):
            # only save if you have all content
            if row['content'] != None:
                create_element(Entry, **row)

            row = build_entry(row, logtype, date, matches)
        else:
            # log(f"parse_log_file(): Threw away some information: {line}", "w")
            pass


def build_entry(row: List, logtype: String, date: String, matches: List) -> List:
    """Build an entry attribute based on the logtype provided"""
    config = get_config()
    
    row['timestamp'] = datetime.strptime(
        date + " " + matches["timestamp"].split(' ')[1], '%y%m%d %H:%M:%S')
    row['timezone'] = matches["timezone"]
    if logtype == "download":
        # # exclude test ips, should not even trigger since create_beacon_from_file is checking already
        # if is_ip_excluded(matches["ipv4"], config.exclusions.internal):
        #     return row
        row['type'] = logtype
        row['content'] = f"{matches['path']}\\{matches['fname']}"
        row['parent_id'] = create_element(Beacon, ip=matches["ipv4"], joined=row["timestamp"], date=date)
    elif logtype == "events":
        # # exclude test ips, should not even trigger since create_beacon_from_file is checking already
        # if is_ip_excluded(matches["ipv4"], config.exclusions.internaly):
        #     return row
        row['type'] = logtype
        row['content'] = matches["content"]
        row['parent_id'] = create_element(Beacon, ip=matches["ipv4"], user=matches["user"],
                                          date=date, hostname=matches["hostname"], joined=row["timestamp"])
    else:
        log(f"build_entry() Failed: Logtype not supported", "e")

    if logtype == "indicator":
        row['content'] = excel_save(row["content"])
    else:
        row['content'] = excel_save(redact(row["content"]))

    return row


# def create_actions():
#     row = {'input': None, 'task': None, 'output': None}
#     entries = get_all_elements(Entry)
#     ci = 0
#     ct = 0
#     co = 0
#     i: int
#     elem: Entry
#     for i, elem in enumerate(entries):
#         ty = elem.type
#         if row["input"] and \
#                 row["task"] and \
#                 row["output"]:
#             create_element(Action, row)
#         elif elem.type == EntryType.output and \
#                 row["task"]:
#             row["task"] = elem.content
#             create_element(Action, row)
#         elif elem.type == EntryType.input and \
#                 row["task"]:
#                     # if input.
