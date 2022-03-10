from os import path
import argparse
from concurrent import futures

from modules.reporting import *
from modules.parser import *
import config

"""
TODO
Map to every task an output
Detect based on the next output if the command was successfull or not
"""


def run(args):
    start = time.time()

    if args.exclude:
        config.exclude = read_file(args.exclude).split("\n")

    init_db(args.database, args.verbose)

    if args.path:
        log_files = get_all_files(args.path, ".log", "beacon")
        ev_files = get_all_files(args.path, ".log", "events")
        dl_files = get_all_files(args.path, ".log", "downloads")

        with futures.ThreadPoolExecutor(max_workers=args.worker) as e:
            # parse all logs
            result_futures = list(
                map(lambda file: e.submit(parse_beacon_log, file), log_files))
            result_futures += list(
                map(lambda file: e.submit(parse_add_log, file), ev_files))
            result_futures += list(
                map(lambda file: e.submit(parse_add_log, file), dl_files))
            for idx, future in enumerate(futures.as_completed(result_futures)):
                printProgressBar(idx, len(result_futures), "Process logs")

            # fill missing beacon_info
            incpl_beacons: List[Beacon] = get_all_incomplete_beacons()
            result_futures = list(map(lambda beacon: e.submit(
                fill_beacon_info, beacon), incpl_beacons))
            for idx, future in enumerate(futures.as_completed(result_futures)):
                printProgressBar(idx, len(result_futures), "Analyzing logs")

    #create_actions()

    if args.minimize:
        remove_clutter()

    if args.output:
        report_input_task(args.output)
        report_dl_ul(args.output)
        report_all_beacons_spawned(args.output)
        report_tiber(args.output)
        report_all_indicators(args.output)

    print(time.time() - start)


class ValidatePath(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        npath = path.abspath(values.strip())
        if not npath:
            return

        if not path.isdir(npath) and not path.isfile(npath):
            log(f"Please choose a valid path for {self.dest}!", "e")
            exit(-1)

        setattr(namespace, self.dest, npath)


if __name__ == "__main__":
    curr_path = path.dirname(path.abspath(__file__))

    parser = argparse.ArgumentParser(
        description='Parse CobaltStrike logs and store them in a DB to create reports')
    parser.add_argument('-w', '--worker', type=int, default=10,
                        help='Set amount of workers: default=10')
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='Activate debugging')
    parser.add_argument('-p', '--path', action=ValidatePath,
                        help='Directory path to start from generating the DB')
    parser.add_argument('-d', '--database', action=ValidatePath, default=curr_path +
                        "\\results\\log.db", help='Database path: default=.\\results\\log.db')
    parser.add_argument('-o', '--output', action=ValidatePath,
                        help='Output path for CSV')
    parser.add_argument('-m', '--minimize', action='store_true',
                        help='Remove unnecessary data: keyloggs,beaconbot,sleep,exit,clear')
    parser.add_argument('-e', '--exclude', action=ValidatePath,
                        help='A file with one IP-Range per line which should be ignored')
    args = parser.parse_args()

    if not args.path and not args.output:
        log("Please select either:\n-g for generating the database\n-o for generating the reports (required at least -g once before)", "e")

    """TODO
    Reports:
    input -> done
    input - output
    file upload - download -> need to change type of upload tasks to upload
    """
    if args.verbose:
        args.worker = 1

    run(args)
