from modules.beacon import *
from modules.entry import *

def parse_beacon_log(file: String) -> None:
    bid, date = create_beacon_from_file(file)    
    if not bid:
        return

    row = {'timestamp': None, 'timezone': None, 'type': None, 'content': None, "parent_id": bid}
    foundMeta = False
    # parse log entries
    lines = open(file, 'r', encoding="UTF-8").readlines()
    for line in lines:
        matches = re.match(config.pattern_line, line, re.MULTILINE)
        
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

            row['timestamp']  =  datetime.strptime(date + " " + matches["timestamp"].split(' ')[1], '%y%m%d %H:%M:%S')
            row['timezone'] = matches["timezone"]
            row['type'] = matches["type"]
            row['content'] = excel_save(redact(matches["content"]))
        elif not matches:
            row['content'] += line
        else:
            log(f"parse_beacon_file(): Threw away some information: {line}", "w")


def parse_add_log(file: String) -> None:
    """Parses the file provided and stores an entry per valid line in the DB"""
    logtype, pattern = get_pattern(file)
    row = {'timestamp': None, 'timezone': None, 'type': None, 'content': None, "parent_id": None}
    
    date = re.findall(config.pattern_date, file, re.MULTILINE)[0]

    # parse log entries
    lines = open(file, 'r', encoding="UTF-8").readlines()
    for line in lines:
        matches = re.match(pattern, line, re.MULTILINE)
        
        # if line is start of a new log entry process, if not append to content
        if matches != None and len(matches.groups()) == 4:
            # only save if you have all content
            if row['content'] != None:
                create_element(Entry, **row)

            row = build_entry(row, logtype, date, matches)
        else:
            pass #log(f"parse_log_file(): Threw away some information: {line}", "w")


def build_entry(row: List, logtype: String, date: String, matches: List) -> List:
    """Build an entry attribute based on the logtype provided"""
    row['timestamp']  =  datetime.strptime(date + " " + matches["timestamp"].split(' ')[1], '%y%m%d %H:%M:%S')
    row['timezone'] = matches["timezone"]
    if logtype == "download":
        # exclude test ips
        if is_ip_in_ranges(matches["ipv4"], config.exclude):
            return row
        row['type'] = logtype
        row['content'] = f"{matches['path']}\{matches['fname']}"
        row['parent_id'] = create_element(Beacon, ip=matches["ipv4"], joined=row["timestamp"], date=date)
    elif logtype == "events":
        # exclude test ips
        if is_ip_in_ranges(matches["ipv4"], config.exclude):
            return row
        row['type'] = logtype
        row['content'] = matches["content"]
        row['parent_id'] = create_element(Beacon, ip=matches["ipv4"], user=matches["user"], date=date, hostname=matches["hostname"], joined=row["timestamp"])
    else:
        log(f"build_entry() Failed: Logtype not supported", "e")
    
    row['content'] = excel_save(redact(row['content']))
    
    return row