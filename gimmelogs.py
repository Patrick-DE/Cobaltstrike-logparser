from os import path
import argparse
from concurrent import futures

from modules.reporting import *
from modules.customparser import *
from modules.configuration import get_config, load_config, config
from modules.utils import get_all_files

from modules.cs_parser_db2 import BeaconLogParser


"""
TODO
Map to every task an output
Detect based on the next output if the command was successfull or not
"""


def run(args):
    global config
    start = time.time()

    if args.exclude:
        load_config(args.exclude)

    config = get_config()
    if config is None:
        log("No configuration loaded!", LogType.ERROR)
        exit(-1)

    init_db(args.database, args.verbose)

    if args.path:
        # log_files = get_all_files(args.path, ".log", "beacon")
        # ev_files = get_all_files(args.path, ".log", "events")
        # dl_files = get_all_files(args.path, ".log", "downloads")

        # with futures.ThreadPoolExecutor(max_workers=args.worker) as e:
        #     # parse all logs
        #     result_futures = list(
        #         map(lambda file: e.submit(parse_beacon_log, file), log_files))
        #     result_futures += list(
        #         map(lambda file: e.submit(parse_additional_log, file), ev_files))
        #     result_futures += list(
        #         map(lambda file: e.submit(parse_additional_log, file), dl_files))
        #     for idx, future in enumerate(futures.as_completed(result_futures)):
        #         printProgressBar(idx, len(result_futures), "Process logs")

        #     # fill missing beacon_info
        #     incpl_beacons: List[Beacon] = get_all_incomplete_beacons()
        #     result_futures = list(map(lambda beacon: e.submit(
        #         fill_beacon_info, beacon), incpl_beacons))
        #     for idx, future in enumerate(futures.as_completed(result_futures)):
        #         printProgressBar(idx, len(result_futures), "Analyzing logs")
        
        ###
        # V2
        ###
        log_files = get_all_files(args.path, ".log", "beacon")
        log_files += get_all_files(args.path, ".log", "events")
        log_files += get_all_files(args.path, ".log", "downloads")
        with futures.ThreadPoolExecutor(max_workers=args.worker) as executor:
            result_futures = list(map(lambda file: executor.submit(BeaconLogParser.parse_beacon_log, file, args.database), log_files))
            for idx, future in enumerate(futures.as_completed(result_futures)):
                print(f"Completed parsing {idx + 1}/{len(result_futures)} logs")

    #create_actions()

    if args.minimize:
        remove_clutter()
        remove_via_ip(config.exclusions.external, True)
        remove_via_ip(config.exclusions.internal, False)
        remove_via_hostname(config.exclusions.hostnames)

    if args.output:
        report_input_task(args.output)
        report_dl_ul(args.output)
        report_all_beacons_spawned(args.output)
        report_all_indicators(args.output)
        report_tiber(args.output)

    print(time.time() - start)


class ValidatePath(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        npath = path.abspath(values.strip())
        if not npath:
            return

        if not path.isdir(npath):
            os.mkdir(npath)
            #log(f"Please choose a valid path for {self.dest}!", "e")
            #exit(-1)

        setattr(namespace, self.dest, npath)

class ValidateFile(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        npath = path.abspath(values.strip())
        if not npath:
            return

        if not path.isfile(npath):
            log(f"Please choose a valid file for {self.dest}!", "e")
            exit(-1)

        setattr(namespace, self.dest, npath)

if __name__ == "__main__":
    curr_path = path.dirname(path.abspath(__file__))

    parser = argparse.ArgumentParser(description='Parse CobaltStrike logs and store them in a DB to create reports')
    parser.add_argument('-w', '--worker', type=int, default=10, help='Set amount of workers: default=10')
    parser.add_argument('-v', '--verbose', action='store_true', help='Activate debugging')
    parser.add_argument('-p', '--path', action=ValidatePath, help='Directory path containing the CS logs')
    parser.add_argument('-d', '--database', action=ValidatePath, help='Database path: default=<path>/log.db')
    parser.add_argument('-o', '--output', action=ValidatePath, help='Output path for CSV: default=<path>/reports/*.csv')
    parser.add_argument('-m', '--minimize', action='store_true', help='Remove unnecessary data: keyloggs,beaconbot,sleep,exit,clear')
    parser.add_argument('-e', '--exclude', action=ValidateFile, help='A file with one IP-Range per line which should be ignored')
    args = parser.parse_args()

    if not args.path and not args.output:
        parser.print_help(sys.stderr)
        log("-----Examples-----", LogType.WARNING)
        log("Recommended:        python3 gimmelogs.py -m -p <LogDir> -e exclude.txt", LogType.WARNING)
        log("Minimum:            python3 gimmelogs.py -p <LogDir>", LogType.WARNING)
        log("Full:               python3 gimmelogs.py -m -w 15 -d <DBDir> -p <LogDir> -o <OutputDir> -e exclude.txt", LogType.WARNING)
        log("Regenerate reports: python3 gimmelogs.py -m -d <DBDir> -e exclude.txt", LogType.WARNING)
        log("--This only works if you have provided the <LogDir> already!", LogType.WARNING)
        exit()

    args.database = os.path.join(args.path, 'log.db')
    args.output = os.path.join(args.path, 'reports')
    if not path.isdir(args.output):
        os.mkdir(args.output)
    """TODO
    Reports:
    input -> done
    input - output
    file upload - download -> need to change type of upload tasks to upload
    """
    if args.verbose:
        args.worker = 1

    run(args)
