import sys, os

class bcolors:
    HEADER = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

vba_trigger_func = ["AutoOpen", "Workbook_Open", "Document_Open"]

def log(text, status="i"):
    """
    Error = e
    Warning = w
    Header = h
    Success = s
    """
    if status == "e":
        print(f"{bcolors.FAIL}[!!] {text} {bcolors.ENDC}")
    elif status == "w":
        print(f"{bcolors.WARNING}[!] {text} {bcolors.ENDC}")
    elif status == "h":
        print(f"{bcolors.HEADER}[-] {text} {bcolors.ENDC}")
    elif status == "s":
        print(f"{bcolors.OKGREEN}[+] {text} {bcolors.ENDC}")
    else:
        print(f"{text}")

def store_to_file(filename, content):
    with open(filename, "w") as text_file:
        print(content, file=text_file)

def read_file(path):
    """path to file will be read as UTF-8 and throw an error + exit if not possible"""
    try:
        with open(path, "r", encoding="utf-8") as f: s = f.read()
    except Exception as ex:
        log(ex.filename + ": " + ex.strerror, "e")
        sys.exit(0)
    return s

def get_all_files(path, extension, prefix=""):
    list_of_files = {}
    for (dirpath, dirnames, filenames) in os.walk(path):
        for filename in filenames:
            if filename.endswith(extension) and filename.startswith(prefix): 
                list_of_files[filename] = os.sep.join([dirpath, filename])
    return list_of_files

def yes_no(question):
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