from datetime import datetime
import os
from modules.sql.sqlite_func import *
from modules.configuration import get_config


def get_beacon_id(file: String):
    """Get the beacon id which is based on the beacon_xxxx.log files name"""
    filename = os.path.basename(file)
    return filename.split("_")[1].split(".")[0]


def fill_beacon_info(beacon: Beacon) -> None:
    """Updates the beacon metadata if not already populated based on the beacons first metadata entry"""
    beacon_info: Dict = {}
    mentry = get_first_metadata_entry_of_beacon(beacon.id)
    if not beacon.hostname and mentry:
        beacon_info = get_beacon_metadata(mentry.content, beacon.date)
    
    eentry = get_last_entry_of_beacon(beacon.id)
    if not beacon.exited and eentry:
        if beacon.date:
            beacon_info["exited"] = eentry.timestamp

    if beacon_info:
        update_element(Beacon, id=beacon.id, **beacon_info)


def get_beacon_metadata(line: str, date: str = None) -> dict:
    """
    Tries to parse the line based on the pattern_metadata.
    
    Args:
        line: Line to parse
        date: Optional date string
    
    Returns:
        Dict with beacon metadata or empty Dict
    """
    config = get_config()
    entry = re.match(config.parsing.cs.line, line)
    if not entry:
        return {}
    
    new_date = None
    if date:
        try:
            timestamp = entry["timestamp"].split(' ')[1]
            new_date = datetime.strptime(f"{date} {timestamp}", '%y%m%d %H:%M:%S')
        except ValueError as e:
            print(f"Failed to parse date: {date} {timestamp}")
    
    matches = re.findall(config.parsing.cs.metadata, entry["content"])
    if len(matches) == 9:
        return {
            "ip_ext": ''.join(matches[0]), 
            "hostname": ''.join(matches[2]), 
            "user": ''.join(matches[3]),
            "process": ''.join(matches[4]),
            "pid": ''.join(matches[5]),
            "joined": new_date
        }
    
    return {}


def create_beacon_from_file(file: String) -> Integer:
    """Creates a beacon based on the file path provided"""
    beacon = {}

    # extract date, ip/unknown and filename from the path
    file = os.path.abspath(file)
    paths = file.split(os.sep)
    beacon["ip"] = paths[len(paths)-2]
    beacon["date"] = paths[len(paths)-3]
    beacon["id"] = get_beacon_id(paths[len(paths)-1])
    # # exclude beacon logs based on internal ip of test machines and everything which is not an IP address
    # if is_ip_excluded(beacon["ip"], config.exclusions.internal):
    #     return None, None

    # beacons without an ID will be ignored, happens usually only with faulty cna scripts:
    # \\unknown\\beacon_aggressor.bridges.DialogBridge$_A@xxx.log'
    # \\unknown\\beacon_.log
    if not beacon["id"] or beacon["id"] == "aggressor":
        return None, None

    return create_element(Beacon, **beacon), beacon["date"]
