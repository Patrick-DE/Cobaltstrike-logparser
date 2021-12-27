from argparse import FileType
import enum
import sys, os, csv
from typing import List

from sqlalchemy.sql.sqltypes import CHAR, Boolean, String

class bcolors (enum.Enum):
    HEADER = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class LogType(enum.Enum):
    """
    Error = RED
    Warning = YELLOW
    Header = BLUE
    Success = GREEN
    INFO = WHITE (default)
    """
    ERROR = 0
    WARNING = 1
    HEADER = 2
    SUCCESS = 3
    INFO = 4
    
def log(text: String, status: LogType=LogType.INFO) -> None:
    if status == LogType.ERROR:
        print(f"{bcolors.FAIL}[!!] {text} {bcolors.ENDC}")
    elif status == LogType.WARNING:
        print(f"{bcolors.WARNING}[!] {text} {bcolors.ENDC}")
    elif status == LogType.HEADER:
        print(f"{bcolors.HEADER}[-] {text} {bcolors.ENDC}")
    elif status == LogType.INFO:
        print(f"{bcolors.OKGREEN}[+] {text} {bcolors.ENDC}")
    else:
        print(f"{text}")

def store_to_file(filename: String, content: String) -> None:
    with open(filename, "w") as text_file:
        print(content, file=text_file)

def write_to_csv(filename: String, header: List, rows: List) -> None:
    with open(filename, 'w', encoding='UTF8', newline="") as f:
        writer = csv.writer(f)
        #writer.writerow("sep=,")
        writer.writerow(header)
        writer.writerows(rows)

def read_file(path: String) -> String:
    """path to file will be read as UTF-8 and throw an error + exit if not possible"""
    try:
        with open(path, "r", encoding="utf-8") as f: s = f.read()
    except Exception as ex:
        log(ex.filename + ": " + ex.strerror, "e")
        sys.exit(0)
    return s

def get_all_files(path: String, extension: String, prefix: String = "") -> List:
    list_of_files = []
    for (dirpath, dirnames, filenames) in os.walk(path):
        for filename in filenames:
            if filename.endswith(extension) and filename.startswith(prefix): 
                list_of_files.append(os.sep.join([dirpath, filename]))
    return list_of_files

def yes_no(question: String) -> Boolean:
    answer = input(question + "(y/n/c): ").lower().strip()
    print("")
    while not(answer == "y" or answer == "n" or answer == "c"):
        print("Input yes, no or cancel")
        answer = input(question + "(y/n/c):").lower().strip()
        print("")
    if answer[0] == "y":
        return True
    elif answer[0] == "c":
        sys.exit(0)
    else:
        return False