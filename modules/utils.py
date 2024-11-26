import enum
import re, sys, os, csv
from typing import List
from sqlalchemy.sql.sqltypes import Boolean, String
from modules.configuration import get_config

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
        print(f"{bcolors.FAIL.value}[!!] {text} {bcolors.ENDC.value}")
    elif status == LogType.WARNING:
        print(f"{bcolors.WARNING.value}[!] {text} {bcolors.ENDC.value}")
    elif status == LogType.HEADER:
        print(f"{bcolors.HEADER.value}[-] {text} {bcolors.ENDC.value}")
    elif status == LogType.INFO:
        print(f"{bcolors.OKGREEN.value}[+] {text} {bcolors.ENDC.value}")
    else:
        print(f"{text}")


def store_to_file(filename: String, content: String) -> None:
    with open(filename, "w") as text_file:
        print(content, file=text_file)


def write_to_csv(filename: String, header: List, rows: List) -> None:
    filename = os.path.abspath(filename.strip())
    while True: 
        try:
            log("Creating csv: " + filename)
            with open(filename, 'w', encoding='UTF8', newline="") as f:
                writer = csv.writer(f, dialect="excel",delimiter=";")
                # writer.writerow("sep=;")
                writer.writerow(header)
                writer.writerows(rows)
        except Exception as ex:
            log("The file is already in use, please close it!","w")
            ret = yes_no("Have you closed the file or do you want to stop the execution?")
            if ret:
                continue
            else:
                break
        break


def read_file(path: String) -> String:
    """path to file will be read as UTF-8 and throw an error + exit if not possible"""
    try:
        filename = os.path.abspath(path.strip())
        with open(filename, "r", encoding="utf-8") as f: s = f.read()
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


# Print iterations progress
def progressBar(iterable, prefix = 'Progress:', suffix = 'Complete', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iterable    - Required  : iterable object (Iterable)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    total = len(iterable)
    # Progress Bar Printing Function
    def printProgressBar (iteration):
        percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        filledLength = int(length * iteration // total)
        bar = fill * filledLength + '-' * (length - filledLength)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    # Initial Call
    printProgressBar(0)
    # Update Progress Bar
    for i, item in enumerate(iterable):
        yield item
        printProgressBar(i + 1)
    # Print New Line on Complete
    print()


# Print iterations progress
def printProgressBar (iteration, total, prefix = '', suffix = 'Complete', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    # Print New Line on Complete
    if iteration == total: 
        print()


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
        content = content.replace(",", ";")
    if "\"" in content:
        content = content.replace("\"", "'")
    return content


def extract_ips(content: String) -> List:
    """
    Extracts IP addresses from a string
    Args:
        content: String to extract IPs from
    Returns:
        List of IP addresses
    """
    return re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", content)