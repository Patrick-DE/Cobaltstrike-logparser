import time
from utils import *
from sqlite_func import *
import re
from concurrent import futures
import argparse

pattern_time = r"(?P<timestamp>(?:\d{2}\/*){2} (?:\d\d:*){3})\s(?P<timezone>\S+)\s"
pattern_line = pattern_time + r"\[(?P<type>\w+)\](?P<content>.*)"
pattern_ipv4 = r"(?P<ipv4>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"
pattern_date = r"\\(?P<date>\d{6})\\"
pattern_metadata = pattern_ipv4 + r"|(?:\w+:\s(.*?);)"
pattern_download = pattern_time + pattern_ipv4 + r"\s\d+\s\d+\s.*?\s(?P<fname>.*)\s(?P<path>\b.*\b)"
pattern_events = pattern_time + r"(?P<content>.*?from\s(?P<User>\b.*\b\s*.*?)@"+ pattern_ipv4 +"\s\((?P<hostname>.*?)\))"


def get_pattern(file):
    fn = os.path.basename(file)
    if "beacon" in fn:
        return "beacon", pattern_line
    elif "downloads" in fn:
        return "download", pattern_download
    elif "events" in fn:
        return "events", pattern_events
    else:
        log(f"get_pattern() Failed: No pattern found", "e")
        exit(1)


def build_entry(row, logtype, date, matches):
    row['timestamp']  =  datetime.strptime(date + " " + matches["timestamp"].split(' ')[1], '%y%m%d %H:%M:%S')
    row['timezone'] = matches["timezone"]
    if logtype == "beacon":
        row['type'] = matches["type"]
        row['content'] = matches["content"]
    elif logtype == "download":
        row['type'] = logtype
        row['content'] = f"{matches['path']}\{matches['fname']}"
        row['parent_id'] = create_beacon(matches["ipv4"]).id
    elif logtype == "events":
        row['type'] = logtype
        row['content'] = matches["content"]
        row['parent_id'] = create_beacon(matches["ipv4"]).id
    else:
        log(f"build_entry() Failed: Logtype not supported", "e")
    return row


def parse_log_file(file):
    logtype, pattern = get_pattern(file)
    # create beacon
    ip = re.match(pattern_ipv4, file)
    date = re.findall(pattern_date, file, re.MULTILINE)
    if date:
        date = date[0]
    else:
        log(f"parse_log_file() Failed: Could not identify the date", "e")
        return None
    
    row = {'timestamp': None, 'timezone': None, 'type': None, 'content': None, "parent_id": None}
    if ip:
        row["parent_id"] = create_beacon(ip[0]).id

    # parse log entries
    lines = open(file, 'r', encoding="UTF-8").readlines()
    for line in lines:
        matches = re.match(pattern, line, re.MULTILINE)
        
        if matches != None and matches.group(3):
            if row['content'] != None:
                create_entry(
                    row['timestamp'], 
                    row["timezone"],
                    row['type'],
                    row['content'],
                    row['parent_id']
                    )

            row = build_entry(row, logtype, date, matches)
        elif not matches and logtype == "beacon":
            row['content'] += line
        else:
            pass #log(f"parse_log_file(): Threw away some information: {line}", "w")


def redact(entry):
    content = entry.content
    r = r"\1[REDACTED]"
    # ntlm
    content = re.sub(r"^(\\$NT\\$)?[a-f0-9]{32}$", r, content)
    # logonpasswords
    content = re.sub(r"(\w+:\d+:)\w+:\w+:::", r, content)
    # password=, pass=
    content = re.sub(r"(.*(?:pass|password|pvk)\s*(?:=|\s|:)\s*)\b\w+\b", r, content)
    # NTLM : , SHA1 : 
    content = re.sub(r"((?:NTLM|SHA1)\s+:\s)\b\w+\b", r, content)
    update_element("Entry", entry.id, {Entry.content: content })


def remove_clutter(entry):
    content = entry.content
    delete = False
    #keylogger output
    if "received keystrokes" in content:
        delete = True
    # sleep commands
    if entry.type == EntryType.input and re.match(r"^sleep(\s\d+)+$", content):
        delete = True
    if "<BeaconBot>" in content or "beacon is late" in content:
        delete = True
    if "received screenshot" in content:
        delete = True
    
    if delete:
        delete_element("Entry", entry.id)


def excel_save(entry):
    content = entry.content
    if "," in content:
        content.replace(",", ";")
        update_element("Entry", entry.id, {Entry.content: content})


def analyze_entries(beacon):
    for entry in beacon.entries:
        remove_clutter(entry)
        redact(entry)
        excel_save(entry)


def fill_beacon_info(id):
    entry = get_first_metadata_entry_of_beacon(id)
    if not entry:
        return

    matches = re.findall(pattern_metadata, entry.content)
    if len(matches) == 9:
        update_beacon(id, {
            Beacon.ip_ext: ''.join(matches[0]), 
            Beacon.hostname: ''.join(matches[2]), 
            Beacon.user: ''.join(matches[3]),
            Beacon.process: ''.join(matches[4]),
            Beacon.pid: ''.join(matches[5])
            })


def analyze(e):
    beacons = get_all_elements("Beacon")
    tasks = []
    for beacon in beacons:
        tasks.append(e.submit(fill_beacon_info, beacon.id))
        tasks.append(e.submit(analyze_entries, beacon))
        
    for task in tasks:
        if task.exception():
            log(task.exception(), "e")


if __name__ == "__main__":
    start = time.time()

    parser = argparse.ArgumentParser(description='Obfuscate VBA code')
    parser.add_argument('-w','--worker',type=int, default=1, help='Set amount of workers')
    parser.add_argument('-f', '--folder', default="", help='Folder path to start to walking for files')
    parser.add_argument('-db', '--database', default = "", help='Database path')
    parser.add_argument('-r', '--redact', action='store_true', help='Redact sensitive values')
    parser.add_argument('-d', '--debug', action='store_true', help='Activate debugging')
    parser.add_argument('-o', '--output', help='Output path for CSV')
    parser.add_argument('-m', '--minimize', help='Remove unnecessary data: keyloggs,beaconbot,sleep')
    args = parser.parse_args()

    curr_path = os.path.dirname(os.path.abspath(__file__))
    if args.database == "":
        args.database =  curr_path + r"\log.db"
    if args.folder == "":
        args.folder = curr_path
    if args.output == None:
        args.output = curr_path + r"\activity.csv"
    if args.debug:
        args.worker = 1
    
    init_db(args.database, args.debug)
    log_files = get_all_files(args.folder, ".log", "beacon")
    ad_files = get_all_files(args.folder, ".log", "downloads")
    ev_files = get_all_files(args.folder, ".log", "events")

    with futures.ThreadPoolExecutor(max_workers=args.worker) as e:
        tasks = []
        # for file in log_files:
        #     tasks.append(e.submit(parse_log_file, file))
        for file in ad_files:
            tasks.append(e.submit(parse_log_file, file))
        for file in ev_files:
            tasks.append(e.submit(parse_log_file, file))
        futures.wait(tasks, timeout=None, return_when=futures.ALL_COMPLETED)

        analyze(e)
        futures.wait(tasks, timeout=None, return_when=futures.ALL_COMPLETED)

    if args.output:
        entries = get_all_entries_filtered(filter=EntryType.input)
        rows = []
        for entry in entries:
            rows.append(entry.to_row())
        header = ["Date", "Time", "Hostname", "Command", "User", "IP"]
        write_to_csv(args.output, header, rows)

    print (time.time() - start)
