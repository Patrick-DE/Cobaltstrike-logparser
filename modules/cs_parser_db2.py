import os
import re
from typing import List, Dict
from sqlalchemy.orm import exc, relationship
from sqlalchemy import select, and_, Column, DateTime, Integer, String, Enum, ForeignKey
from modules.sql.sqlite_func import init_db
from modules.sql.sqlite_model import EntryType, Beacon, Entry
import threading
from datetime import datetime

class BeaconLogParser:
    def __init__(self, filepath: str, db_path: str, debug: bool = False):
        self.filepath = filepath
        self.parsed_data = []
        # Extract beacon ID from the filename
        self.beacon_id = self.extract_beacon_id_from_filename(filepath)
        # Extract date from the folder name
        self.year_prefix = self.extract_year_prefix_from_filepath(filepath)
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
        match = re.search(r'beacon_(\d+)', filename)
        if match:
            return int(match.group(1))
        else:
            raise ValueError("Beacon ID could not be extracted from the filename.")

    @staticmethod
    def extract_year_prefix_from_filepath(filepath: str) -> str:
        match = re.search(r'(\d{6})', os.path.dirname(filepath))
        if match:
            return match.group(1)[:2]
        else:
            raise ValueError("Year prefix could not be extracted from the folder name.")

    @staticmethod
    def parse_beacon_log(filepath: str, db_path: str, debug: bool = False):
        parser = BeaconLogParser(filepath, db_path, debug)
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
            # if self.current_command:
            #     self.store_entry_to_db(self.current_command)
            if self.current_output:
                self.store_entry_to_db({'type': 'output', 'timestamp': self.current_command['timestamp'], 'timezone': self.current_command["timezone"], 'content': self.current_output.strip()})

    def parse_line(self, line: str) -> Dict:
        # Regular expressions for different log formats
        metadata_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[metadata\] (?P<ip_ext>[\d\.]+) <- (?P<ip_int>[\d\.]+); computer: (?P<computer>.*?); user: (?P<user>.*?); process: (?P<process>.*?); pid: (?P<pid>\d+); os: (?P<os>.*?); version: (?P<version>.*?); build: (?P<build>.*?); beacon arch: (?P<arch>.*)')
        input_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[input\] <(?P<operator>.*?)> (?P<command>.*)')
        output_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[output\](?P<output>.*)')
        task_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[task\] <(?P<operator>.*?)> (?P<task_description>.*)')
        checkin_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[checkin\] host called home, sent: (?P<bytes_sent>\d+) bytes')
        received_output_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[output\]\s*received output:')
        event_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \*\*\* (?P<event_description>.*)')
        download_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+))\t(?P<source_ip>[\d\.]+)\t(?P<session_id>\d+)\t(?P<size>\d+)\t(?P<server_path>.+?)\t(?P<file_name>.+?)\t(?P<local_path>.+)')
        error_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[error\] (?P<error_message>.*)')
        job_registered_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[job_registered\] job registered with id (?P<job_id>\d+)')
        job_completed_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[job_completed\] job (?P<job_id>\d+) completed')
        indicator_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[indicator\] file: (?P<file_hash>\w+) (?P<file_size>\d+) bytes (?P<file_path>.+)')

        metadata_match = metadata_pattern.match(line)
        input_match = input_pattern.match(line)
        output_match = output_pattern.match(line)
        task_match = task_pattern.match(line)
        checkin_match = checkin_pattern.match(line)
        received_output_match = received_output_pattern.match(line)
        event_match = event_pattern.match(line)
        download_match = download_pattern.match(line)
        error_match = error_pattern.match(line)
        job_registered_match = job_registered_pattern.match(line)
        job_completed_match = job_completed_pattern.match(line)
        indicator_match = indicator_pattern.match(line)

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
        elif task_match:
            return {
                'type': 'task',
                'timestamp': self.parse_timestamp(self, task_match.group('timestamp')),
                'timezone': task_match.group('timezone'),
                'ttp': task_match.group('operator'),
                'content': task_match.group('task_description'),
            }
        elif checkin_match:
            return {
                'type': 'checkin',
                'timestamp': self.parse_timestamp(self, checkin_match.group('timestamp')),
                'timezone': checkin_match.group('timezone'),
                'content': checkin_match.group('bytes_sent'),
            }
        elif received_output_match:
            return {
                'type': 'received_output',
                'timestamp': self.parse_timestamp(self, received_output_match.group('timestamp')),
                'timezone': received_output_match.group('timezone'),
            }
        elif event_match:
            return {
                'type': 'event',
                'timestamp': self.parse_timestamp(self, event_match.group('timestamp')),
                'timezone': event_match.group('timezone'),
                'content': event_match.group('event_description').strip(),
            }
        elif download_match:
            return {
                'type': 'download',
                'timestamp': self.parse_timestamp(self, download_match.group('timestamp')),
                'timezone': download_match.group('timezone'),
                'source_ip': download_match.group('source_ip'),
                'session_id': download_match.group('session_id'),
                'size': download_match.group('size'),
                'server_path': download_match.group('server_path'),
                'file_name': download_match.group('file_name'),
                'local_path': download_match.group('local_path'),
            }
        elif error_match:
            return {
                'type': 'error',
                'timestamp': self.parse_timestamp(self, error_match.group('timestamp')),
                'timezone': error_match.group('timezone'),
                'content': error_match.group('error_message').strip(),
            }
        elif job_registered_match:
            return {
                'type': 'job_registered',
                'timestamp': self.parse_timestamp(self, job_registered_match.group('timestamp')),
                'timezone': job_registered_match.group('timezone'),
                'content': job_registered_match.group('job_id').strip(),
            }
        elif job_completed_match:
            return {
                'type': 'job_completed',
                'timestamp': self.parse_timestamp(job_completed_match.group('timestamp')),
                'content': job_completed_match.group('job_id').strip(),
            }
        elif indicator_match:
            return {
                'type': 'indicator',
                'timestamp': self.parse_timestamp(indicator_match.group('timestamp')),
                'file_hash': indicator_match.group('file_hash'),
                'file_size': indicator_match.group('file_size'),
                'file_path': indicator_match.group('file_path').strip(),
            }
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
