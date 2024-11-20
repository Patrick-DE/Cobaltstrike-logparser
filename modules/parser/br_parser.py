import os
import re
from typing import List, Dict
from sqlalchemy.orm import exc, relationship
from sqlalchemy import select, and_, Column, DateTime, Integer, String, Enum, ForeignKey
from modules.sql.sqlite_func import init_db
from modules.sql.sqlite_model import EntryType, Beacon, Entry
import threading
from datetime import datetime

class BRLogParser:
    def __init__(self, filepath: str, db_path: str, debug: bool = False):
        self.filepath = filepath
        self.parsed_data = []
        # Extract beacon ID from the filename
        self.beacon_id = self.extract_beacon_id_from_filename(filepath)
        # Initialize the database session
        session_manager = init_db(db_path, debug)
        self.session = session_manager()
        # Track the current command and its accumulated output
        self.current_command = None
        self.current_output = ""
        self.is_accumulating_output = False
        # Lock for thread-safe database access
        self.lock = threading.Lock()

    @staticmethod
    def extract_beacon_id_from_filename(filename: str) -> int:
        match = re.search(r'b-(\d+)', filename)
        if match:
            return int(match.group(1))
        else:
            pass

    @staticmethod
    def parse_beacon_log(filepath: str, db_path: str, debug: bool = False):
        parser = BRLogParser(filepath, db_path, debug)
        parser.parse()

    def parse(self):
        with open(self.filepath, 'r') as file:
            for line in file:
                if line == "\n" or line == "":
                    continue
                
                parsed_line = self.parse_line(line)
                if parsed_line and self.is_accumulating_output and parsed_line['type'] != 'output':
                    # store the output of the previous command
                    self.store_entry_to_db({'type': 'output', 'timestamp': self.current_command['timestamp'], 'timezone': self.current_command["timezone"], 'content': self.current_output.strip()})
                    self.current_command = parsed_line
                    self.current_output = ""
                    self.is_accumulating_output = False
                if parsed_line:
                    # Handle metadata separately to store or update beacon information
                    if parsed_line['type'] == 'metadata':
                        self.store_beacon_to_db(parsed_line)
                    # if new command is found, store the new command and the old output
                    elif parsed_line['type'] == 'input':
                        # store finished entry with its output
                        if self.current_output:
                            self.store_entry_to_db({'type': 'output', 'timestamp': self.current_command['timestamp'], 'timezone': self.current_command["timezone"], 'content': self.current_output.strip()})
                        
                        self.store_entry_to_db(parsed_line)
                        # Reset for the new command
                        self.current_command = parsed_line
                        self.current_output = ""
                        self.is_accumulating_output = False
                    elif parsed_line['type'] == 'output' or parsed_line['type'] == 'received_output' or parsed_line['type'] == 'error':
                        # Accumulate output for the current command
                        self.is_accumulating_output = True
                        if 'output' in parsed_line:
                            self.current_output += parsed_line['output']
                    else:
                        # Store any other type of entry immediately
                        if self.current_command and self.current_output:
                            # self.store_entry_to_db({'type': 'output', 'timestamp': self.current_command['timestamp'], 'timezone': self.current_command["timezone"], 'content': self.current_output.strip()})
                            self.current_command = None
                            self.current_output = ""
                            self.is_accumulating_output = False
                        self.store_entry_to_db(parsed_line)
                else:
                    # add the output to the current command
                    if self.is_accumulating_output:
                        self.current_output += line
                    else:
                        print(f"Could not parse {self.filepath} - {line}")
            # Last line of the file: Store the last command of the file and its output if applicable
            if self.current_output:
                self.store_entry_to_db({'type': 'output', 'timestamp': self.current_command['timestamp'], 'timezone': self.current_command["timezone"], 'content': self.current_output.strip()})

    def parse_line(self, line: str) -> Dict:
        # Regular expressions for different log formats
        metadata_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[::badger authenticated from (?P<ips>.*)\]\[(?P<user>.*?)\]\[b-(?P<beacon>\d+?).*\]')
        input_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[input\] (?P<operator>.*?) => (?P<command>.*)')
        output_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[sent \d+ bytes\]')
        # output_pattern = re.compile(r'\[\*\] (?P<output>.*)')
        http_log_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} UTC)\s+\[\+\] Verb: (?P<verb>\w+)\s+\[\+\] Remote Address: (?P<remote_address>[\d\.]+:\d+)\s+\[\+\] Request URI: (?P<request_uri>.*)')
        http2_log_patter = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+))\s+\[\+\] b-(?P<id>\d+)\s+.*: \[(?P<ips>.*)\]')
        watchlist_pattern = re.compile(r'(?P<Date>\d{2}-\d{2}-\d{4})\s+(?P<Time>\d{2}:\d{2}:\d{2})\s+(?P<TimeZone>\w+)\s+\[Initial\ Access\]\s+b-(?P<Identifier>\d+)\\\\[A-Z0-9]+\s+\((?P<HostUser>.+)\)\s+from\s+(?P<IPs>.+)\s+\[(?P<Num1>\d+)->(?P<Num2>\d+)\]')
        upload_log_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[UPLOAD\] Host: (?P<host>.*) \| File: (?P<file_name>.*) \| MD5: (?P<md5>[a-f0-9]{32})')
        deauth_log_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) (?P<message>.*) \((?P<name>\w+)\): \[b-(?P<id>\d+).*\]\s+\[\+\] Verb: (?P<verb>\w+)\s+\[\+\] Remote Address: (?P<remote_address>[\d\.]+):\d+\s+\[\+\] Request URI: (?P<request_uri>.*)')
        
        metadata_match = metadata_pattern.match(line)
        input_match = input_pattern.match(line)
        output_match = output_pattern.match(line)
        http_log_match = http_log_pattern.match(line)
        http2_log_pattern = http2_log_patter.match(line)
        watchlist_match = watchlist_pattern.match(line)
        upload_log_match = upload_log_pattern.match(line)
        deauth_log_match = deauth_log_pattern.match(line)

        if metadata_match:
            return {
                'type': 'metadata',
                'timestamp': self.parse_timestamp(self, metadata_match.group('timestamp')),
                'ip': metadata_match.group('ip_int'),
                'ip_ext': metadata_match.group('ip_ext'),
                'computer': metadata_match.group('computer'),
                'user': metadata_match.group('user'),
                'process': metadata_match.group('process'),
                'pid': metadata_match.group('pid'),
                'os': metadata_match.group('os'),
                'version': metadata_match.group('version'),
                'build': metadata_match.group('build'),
                'arch': metadata_match.group('arch'),
            }
        elif input_match:
            return {
                'type': 'input',
                'timestamp': self.parse_timestamp(self, input_match.group('timestamp')),
                'timezone': input_match.group('timezone'),
                'operator': input_match.group('operator'),
                'content': input_match.group('command'),
            }
        elif output_match:
            return {
                'type': 'output',
                'timestamp': self.parse_timestamp(self, output_match.group('timestamp')),
                'timezone': output_match.group('timezone'),
                'content': output_match.group('output').strip(),
            }
        elif http_log_match:
            return {
                'type': 'task',
                'timestamp': self.parse_timestamp(self, http_log_match.group('timestamp')),
                'timezone': http_log_match.group('timezone'),
                'ttp': http_log_match.group('operator'),
                'content': http_log_match.group('task_description'),
            }
        elif http2_log_pattern:
            return {
                'type': 'checkin',
                'timestamp': self.parse_timestamp(self, http2_log_pattern.group('timestamp')),
                'timezone': http2_log_pattern.group('timezone'),
                'content': http2_log_pattern.group('bytes_sent'),
            }
        elif watchlist_match:
            return {
                'type': 'received_output',
                'timestamp': self.parse_timestamp(self, watchlist_match.group('timestamp')),
                'timezone': watchlist_match.group('timezone'),
            }
        elif upload_log_match:
            return {
                'type': 'event',
                'timestamp': self.parse_timestamp(self, upload_log_match.group('timestamp')),
                'timezone': upload_log_match.group('timezone'),
                'content': upload_log_match.group('event_description').strip(),
            }
        elif deauth_log_match:
            return {
                'type': 'download',
                'timestamp': self.parse_timestamp(self, deauth_log_match.group('timestamp')),
                'timezone': deauth_log_match.group('timezone'),
            }
        # elif error_match:
        #     return {
        #         'type': 'error',
        #         'timestamp': self.parse_timestamp(self, error_match.group('timestamp')),
        #         'timezone': error_match.group('timezone'),
        #         'content': error_match.group('error_message').strip(),
        #     }
        # elif job_registered_match:
        #     return {
        #         'type': 'job_registered',
        #         'timestamp': self.parse_timestamp(self, job_registered_match.group('timestamp')),
        #         'timezone': job_registered_match.group('timezone'),
        #         'content': job_registered_match.group('job_id').strip(),
        #     }
        # elif job_completed_match:
        #     return {
        #         'type': 'job_completed',
        #         'timestamp': self.parse_timestamp(job_completed_match.group('timestamp')),
        #         'content': job_completed_match.group('job_id').strip(),
        #     }
        # elif indicator_match:
        #     return {
        #         'type': 'indicator',
        #         'timestamp': self.parse_timestamp(indicator_match.group('timestamp')),
        #         'file_hash': indicator_match.group('file_hash'),
        #         'file_size': indicator_match.group('file_size'),
        #         'file_path': indicator_match.group('file_path').strip(),
        #     }
        return None

    @staticmethod
    def parse_timestamp(self, timestamp_str: str) -> datetime:
        # get the current year
        return datetime.strptime(self.year_prefix + "/" + timestamp_str, "%y/%m/%d %H:%M:%S %Z")

    def store_entry_to_db(self, entry_data: Dict):
        entry_type = EntryType[entry_data['type']]
        entry_data['parent_id'] = self.beacon_id
        try:
            # Sanity check to avoid adding duplicate entries
            with self.lock:
                existing_entry = self.session.query(Entry).filter_by(
                    timestamp=entry_data['timestamp'],
                    timezone=entry_data['timezone'],
                    type=entry_type,
                    parent_id=self.beacon_id
                ).one_or_none()

                if existing_entry is None:
                    entry = Entry(**entry_data)
                    self.session.add(entry)
                else:
                    # update the entry object
                    existing_entry.ttp = entry_data['ttp'] if 'ttp' in entry_data else None
                    existing_entry.operator = entry_data['operator'] if 'operator' in entry_data else None
                    existing_entry.content = entry_data['content'] if 'content' in entry_data else None
                    self.session.add(existing_entry)
                    
                self.session.commit()
        except Exception as e:
            self.session.rollback()
            print(f"Failed to insert log entry: {e}")

    def store_beacon_to_db(self, metadata: Dict):
        try:
            # Sanity check to avoid adding duplicate beacons
            with self.lock:
                existing_beacon = self.session.query(Beacon).filter_by(
                    id=self.beacon_id
                ).one_or_none()

                if existing_beacon is None:
                    beacon = Beacon(
                        id=self.beacon_id,
                        ip=metadata['ip'],
                        ip_ext=metadata['ip_ext'],
                        hostname=metadata['computer'],
                        user=metadata['user'],
                        process=metadata['process'],
                        pid=metadata['pid'],
                        os=metadata['os'],
                        version=metadata['version'],
                        build=metadata['build'],
                        arch=metadata['arch'],
                        timestamp=metadata['timestamp'],
                    )
                    self.session.add(beacon)
                else:
                    existing_beacon.ip = metadata['ip']
                    existing_beacon.ip_ext = metadata['ip_ext']
                    existing_beacon.hostname = metadata['computer']
                    existing_beacon.user = metadata['user']
                    existing_beacon.process = metadata['process']
                    existing_beacon.pid = metadata['pid']
                    existing_beacon.os = metadata['os']
                    existing_beacon.version = metadata['version']
                    existing_beacon.build = metadata['build']
                    existing_beacon.arch = metadata['arch']
                    existing_beacon.timestamp = metadata['timestamp']
                    self.session.add(existing_beacon)
                    
                self.session.commit()
        except Exception as e:
            self.session.rollback()
            print(f"Failed to insert or update beacon: {e}")
