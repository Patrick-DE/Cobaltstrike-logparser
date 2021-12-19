import time
from utils import *
from sqlite_func import *
import re
from concurrent import futures
import argparse

pattern_line = r"(?P<timestamp>(?:\d{2}\/*){2} (?:\d\d:*){3})\s(?P<timezone>\S+)\s\[(?P<type>\w+)\](?P<content>.*)"
pattern_ipv4 = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
pattern_date = r"(\d{6})\W(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
pattern_metadata = r"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)|(?:\w+:\s(.*?);)"

def parse_file(file):
    ip = re.findall(pattern_ipv4, file)
    date = re.findall(pattern_date, file, re.MULTILINE)
    if ip and date:
        record = create_beacon(ip[0])
        date = date[0]
    else:
        return
    lines = open(file, 'r').readlines()
    row = {'timestamp': None, 'timezone': None, 'type': None, 'content': None}
    for line in lines:
        matches = re.match(pattern_line, line, re.MULTILINE)
        
        if matches != None and matches.group(3):
            if row['content'] != None:
                create_entry(
                    timestamp= row['timestamp'], 
                    timezone=row["timezone"],
                    type = row['type'],
                    content = row['content'],
                    parent_id= record.id
                    )

            row['timestamp']  =  datetime.strptime(date + " " + matches.group(1).split(' ')[1], '%y%m%d %H:%M:%S')
            row['timezone'] = matches.group(2)
            row['type'] = matches.group(3)
            row['content'] = matches.group(4)
        else:
            row['content'] += line


def redact(entry):
    content = entry.content
    r = r"\1[REDACTED]"
    # ntlm
    content = re.sub(r"^(\\$NT\\$)?[a-f0-9]{32}$", r, content)
    # logonpasswords
    content = re.sub(r"(\w+:\d+:)\w+:\w+:::", r, content)
    # password=, pass=
    content = re.sub(r"(.*(?:pass|password)\s*(?:=|\s|:)\s*)\b\w+\b", r, content)
    # NTLM : , SHA1 : 
    content = re.sub(r"((?:NTLM|SHA1)\s+:\s)\b\w+\b", r, content)
    update_entry(entry.id, {Entry.content: content })


def remove_keystroke_entries(entry):
    content = entry.content
    if "received keystrokes" in content:
        delete_entry(entry.id)


def analyze_entries(id):
    entries = get_all_entries_of_beacon(id)
    for entry in entries:
        remove_keystroke_entries(entry)
        redact(entry)


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
    beacons = get_all_beacons()
    tasks = []
    for beacon in beacons:
        tasks.append(e.submit(fill_beacon_info, beacon.id))
        tasks.append(e.submit(analyze_entries, beacon.id))
        
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
    args = parser.parse_args()

    curr_path = os.path.dirname(os.path.abspath(__file__))
    if args.database == "":
        args.database =  curr_path + r"\log.db"
    if args.folder == "":
        args.folder = curr_path
    if args.debug:
        args.worker = 1
    
    init_db(args.database, args.debug)
    files = get_all_files(args.folder, ".log", "beacon")
    
    with futures.ThreadPoolExecutor(max_workers=args.worker) as e:
        tasks = []
        #for file in files.items():
        #    tasks.append(e.submit(parse_file, file[1]))
        
        #futures.wait(tasks, timeout=None, return_when=futures.ALL_COMPLETED)
        analyze(e)

    print (time.time() - start)
