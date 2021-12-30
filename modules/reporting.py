from modules.sql.sqlite_func import *
from modules.utils import *

def sort_on_timestamp(elem: Entry):
    return elem.timestamp
def sort_on_joined(elem: Beacon):
    return elem.joined

def report_input_task(o):
    # input report
    entries = get_all_entries_filtered(filter=EntryType.input)
    entries = entries + get_all_entries_filtered(filter=EntryType.task)
    entries.sort(key=sort_on_timestamp)
    rows = []
    for entry in entries:
        rows.append(entry.to_row())
    header = ["Date", "Time", "Hostname", "Command", "User", "IP"]
    write_to_csv(o+"\\activity-report.csv", header, rows)

def report_dl_ul(o):
    # get download and upload report
    entries = get_all_entries_filtered(filter=EntryType.download)
    entries = entries + get_upload_entries()
    entries.sort(key=sort_on_timestamp)
    rows = []
    for entry in entries:
        rows.append(entry.to_row())
    header = ["Date", "Time", "Hostname", "File", "User", "IP"]
    write_to_csv(o+"\\dl-ul-report.csv", header, rows)

def report_all_beacons_spawned(o):
    entries = get_all_complete_beacons()
    entries.sort(key=sort_on_joined)
    rows = []
    for entry in entries:
        rows.append(entry.to_row())
    header = ["Hostname", "IP", "Internet via IP", "User", "Process", "Process ID", "Joined", "Exited"]
    write_to_csv(o+"\\beacon-report.csv", header, rows)