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
pattern_metadata = pattern_ipv4 + r"|(?:\w+:\s(.*?);)|(?P<beacon>\w+_\d+)"
pattern_download = pattern_time + pattern_ipv4 + r"\s\d+\s\d+\s.*?\s(?P<fname>.*)\t(?P<path>\b.*\b)"
pattern_events = pattern_time + r"(?P<content>.*?from\s(?P<user>\b.*\b\s*.*?)@"+ pattern_ipv4 +"\s\((?P<hostname>.*?)\))"
gExclude = []


def parse_beacon_metadata(line, date=None):
    """Tries to parse the line based on the pattern_metadata.
    
    Returns:
    - Dict with beacon metadata
    - Empty Dict"""
    entry = re.match(pattern_line, line)
    if not entry:
        return {}
    
    if date:
        new_date = datetime.strptime(date + " " + entry["timestamp"].split(' ')[1], '%y%m%d %H:%M:%S')

    matches = re.findall(pattern_metadata, entry["content"])
    if len(matches) == 9:
        return {
            "ip_ext":''.join(matches[0]), 
            "hostname":''.join(matches[2]), 
            "user":''.join(matches[3]),
            "process":''.join(matches[4]),
            "pid":''.join(matches[5]),
            "joined":new_date
        }
    else:
        #log(f"parse_beacon_metadata(): Did not detect metadata: {line}", "w")
        return {}


def get_beacon_id(file):
    """Get the beacon id which is based on the beacon_xxxx.log files name"""
    filename = os.path.basename(file)
    return filename.split("_")[1].split(".")[0]


def create_all_beacons(file):
    """Stores all beacons detected via the event.log in the DB"""
    date = re.findall(pattern_date, file, re.MULTILINE)[0]
    bid = get_beacon_id(file)
    if bid == "aggressor":
        return

    lip = re.findall(pattern_ipv4, file)
    if lip:
        lip = lip[0]
        # exclude test ips
        if is_ip_in_ranges(lip, gExclude):
            return
    else:
        lip = "unknown"

    with open(file) as f:
        first_line = f.readline()
        beacon_info = parse_beacon_metadata(first_line, date)

    create_element(Beacon, id=bid, ip=lip, date=date, **beacon_info)


def get_pattern(file):
    """Returns the pattern based on the filepath provided.
    The following pattern are available:
    - beacon_xxx.log : pattern_line
    - downloads.log : pattern_download
    - events.log : pattern_events"""
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
    """Build an entry attribute based on the logtype provided"""
    row['timestamp']  =  datetime.strptime(date + " " + matches["timestamp"].split(' ')[1], '%y%m%d %H:%M:%S')
    row['timezone'] = matches["timezone"]
    if logtype == "beacon":
        row['type'] = matches["type"]
        row['content'] = matches["content"]
    elif logtype == "download":
        # exclude test ips
        if is_ip_in_ranges(matches["ipv4"], gExclude):
            return
        row['type'] = logtype
        row['content'] = f"{matches['path']}\{matches['fname']}"
        row['parent_id'] = create_element(Beacon, ip=matches["ipv4"], joined=row["timestamp"], date=date)
    elif logtype == "events":
        # exclude test ips
        if is_ip_in_ranges(matches["ipv4"], gExclude):
            return
        row['type'] = logtype
        row['content'] = matches["content"]
        row['parent_id'] = create_element(Beacon, ip=matches["ipv4"], user=matches["user"], date=date, hostname=matches["hostname"], joined=row["timestamp"])
    else:
        log(f"build_entry() Failed: Logtype not supported", "e")
    return row


def parse_log_file(file):
    """Parses the file provided and stores an entry per valid line in the DB"""
    logtype, pattern = get_pattern(file)
    row = {'timestamp': None, 'timezone': None, 'type': None, 'content': None, "parent_id": None}
    
    date = re.findall(pattern_date, file, re.MULTILINE)[0]
    if "beacon" in logtype:
        row["parent_id"] = get_beacon_id(file)
    

    # parse log entries
    lines = open(file, 'r', encoding="UTF-8").readlines()
    for line in lines:
        matches = re.match(pattern, line, re.MULTILINE)
        
        if matches != None and matches.group(3):
            if row['content'] != None:
                create_element(Entry, **row)

            row = build_entry(row, logtype, date, matches)
        elif not matches and logtype == "beacon":
            row['content'] += line
        else:
            pass #log(f"parse_log_file(): Threw away some information: {line}", "w")


def redact(entry):
    """This function replaces the following entry.content with [REDACTED] in the DB:
    - NTLM hashes, based on regex
    - logonpasswords
    - [-](password|pass|p|pkv)[\s|=|:]
    - (NTLM|SHA1) :
    """
    content = entry.content
    r = r"\1[REDACTED]"
    # password=, pass=, pvk=, -p:
    content = re.sub(r"((?:\/|-+|\s)(?:p|pass|password|pvk)\s*(?:=|\s|:)\s*)\S+", r, content, re.I)
    # NTLM : , SHA1 : 
    content = re.sub(r"((?:NTLM|SHA1)\s+:\s)\b\w+\b", r, content, re.I)
    # logonpasswords
    content = re.sub(r"(\w+:\d+:)\w+:\w+:::", r, content)
    # /aes265:, /rc4:, /statekey:
    content = re.sub(r"(.*\/(?:aes256|rc4|statekey)\s*(?:=|:)\s*)(.*?)\s*$", r, content, re.I)
    # make_token
    content = re.sub(r"(make_token .*\s)(.*)", r, content, re.I)
    update_element(Entry, id=entry.id, content=content)
    # ntlm
    content = re.sub(r"^(\\$NT\\$)?[a-f0-9]{32}$", r, content)
    # redact strings which have 32bites or 64 like aes265
    content = re.sub(r"\b([A-Fa-f0-9]{64}|[A-Fa-f0-9]{32})\b", r, content)


def excel_save(entry):
    """Replaces the csv seperator ',' with ';'"""
    content = entry.content
    if "," in content:
        content.replace(",", ";")
        update_element(Entry, id=entry.id, content=content)


def analyze_entries(beacon):
    """Iterating over the entries associated with the beacon and executing the following functions:
    - remove_clutter
    - redact
    - excel_save"""
    remove_clutter()
    for entry in beacon.entries:
        redact(entry)
        excel_save(entry)


def fill_beacon_info(beacon):
    """Updates the beacon metadata if not already populated based on the beacons first metadata entry"""
    beacon_info: Dict = {}
    mentry = get_first_metadata_entry_of_beacon(beacon.id)
    if not beacon.hostname and mentry:
        beacon_info = parse_beacon_metadata(mentry.content, beacon.date)
    
    eentry = get_last_entry_of_beacon(beacon.id)
    if not beacon.exited and eentry:
        if beacon.date:
            beacon_info["exited"] = eentry.timestamp

    if beacon_info:
        update_element(Beacon, id=beacon.id, **beacon_info)


def sort_on_timestamp(elem: Entry):
    return elem.timestamp

def reporting(args):
    # input report
    entries = get_all_entries_filtered(filter=EntryType.input)
    entries = entries + get_all_entries_filtered(filter=EntryType.task)
    entries.sort(key=sort_on_timestamp)
    rows = []
    for entry in entries:
        rows.append(entry.to_row())
    header = ["Date", "Time", "Hostname", "Command", "User", "IP"]
    write_to_csv(args.output, header, rows)

    # get download and upload report
    entries = get_all_entries_filtered(filter=EntryType.download)
    entries = entries + get_all_entries_filtered(filter=EntryType.upload)
    entries.sort(key=sort_on_timestamp)
    rows = []
    for entry in entries:
        rows.append(entry.to_row())
    header = ["Date", "Time", "Hostname", "File", "User", "IP"]
    write_to_csv("activity_dl.csv", header, rows)

def run(args):
    global gExclude
    start = time.time()

    if args.exclude_path:
        try:
            gExclude = read_file(args.exclude_path).split("\n")
        except:
            log("Please ensure your exception file has the correct format!", "e")

    init_db(args.database_path, args.debug)

    log_files = get_all_files(args.folder, ".log", "beacon")
    ev_files = get_all_files(args.folder, ".log", "events")
    dl_files = get_all_files(args.folder, ".log", "downloads")

    with futures.ThreadPoolExecutor(max_workers=args.worker) as e:
        ##create all beacons
        result_futures = list(map(lambda file: e.submit(create_all_beacons, file), log_files))
        for idx, future in enumerate(futures.as_completed(result_futures)):
            printProgressBar(idx, len(result_futures), "Creating Beacons")
        ##futures.wait(result_futures, timeout=None, return_when=futures.ALL_COMPLETED)
        
        result_futures = list(map(lambda file: e.submit(parse_log_file, file), log_files))
        result_futures += list(map(lambda file: e.submit(parse_log_file, file), ev_files))
        result_futures += list(map(lambda file: e.submit(parse_log_file, file), dl_files))
        for idx, future in enumerate(futures.as_completed(result_futures)):
            printProgressBar(idx, len(result_futures), "Process logs")

        beacons = get_all_elements(Beacon)
        result_futures = list(map(lambda beacon: e.submit(fill_beacon_info, beacon), beacons))
        result_futures += list(map(lambda beacon: e.submit(analyze_entries, beacon), beacons))
        for idx, future in enumerate(futures.as_completed(result_futures)):
            printProgressBar(idx, len(result_futures), "Analyzing logs")

    if args.output:
        reporting(args)

    print (time.time() - start)

if __name__ == "__main__":
    curr_path = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(description='parse CobaltStrike logs and store them in a DB to create reports')
    parser.add_argument('-w','--worker',type=int, default=10, help='Set amount of workers')
    parser.add_argument('-f', '--folder', default=curr_path, help='Folder path to start to walking for files')
    parser.add_argument('-dp', '--database-path', default= curr_path+r"\log.db", help='Database path')
    parser.add_argument('-r', '--redact', action='store_true', help='Redact sensitive values')
    parser.add_argument('-d', '--debug', action='store_true', help='Activate debugging')
    parser.add_argument('-o', '--output', default="", help='Output path for CSV')
    parser.add_argument('-m', '--minimize', help='Remove unnecessary data: keyloggs,beaconbot,sleep')
    parser.add_argument('-e', '--exclude-path', help='A file with one IP-Range per line which should be ignored')
    args = parser.parse_args()

    """TODO
    Reports:
    input -> done
    input - output
    file upload - download -> need to change type of upload tasks to upload
    """
    if args.debug:
        args.worker = 1

    run(args)