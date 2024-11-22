import re
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum, create_engine
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from typing import Dict
from modules.sql.sqlite_func import init_db
from modules.sql.sqlite_model import Beacon, Entry, EntryType
from modules.utils import extract_ips

class BRLogParser:
    def __init__(self, filepath: str, db_path: str, debug: bool = False):
        self.filepath = filepath
        self.multiline_buffer = {}
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
            raise ValueError("Beacon ID could not be extracted from the filename.")

    @staticmethod
    def parse_beacon_log(filepath: str, db_path: str, debug: bool = False):
        parser = BRLogParser(filepath, db_path, debug)
        parser.parse()
        
    @staticmethod
    def parse_timestamp(timestamp_str: str) -> datetime:
        # get the current year
        return datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S %Z")

    def parse(self):
        with open(self.filepath, 'r') as file:
            for line in file:
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
                    elif parsed_line['type'] == 'output':
                        # Accumulate output for the current command
                        self.is_accumulating_output = True
                        self.current_output += parsed_line['content'] + "\n"
                    else:
                        # Store any other type of entry immediately
                        if self.current_command and self.current_output:
                            self.store_entry_to_db({'type': 'output', 'timestamp': self.current_command['timestamp'], 'timezone': self.current_command["timezone"], 'content': self.current_output.strip()})
                            self.current_command = None
                            self.current_output = ""
                            self.is_accumulating_output = False
                        self.store_entry_to_db(parsed_line)
                else:
                    # add the output to the current command
                    if self.is_accumulating_output:
                        self.current_output += line
                    elif re.match(r'^\s*$', line):
                        continue
                    else:
                        if "watchlist.log" in self.filepath:
                            pass
                        else:
                            print(f"Could not parse {self.filepath} - {line}")
            # Last line of the file: Store the last command of the file and its output if applicable
            if self.current_output:
                self.store_entry_to_db({'type': 'output', 'timestamp': self.current_command['timestamp'], 'timezone': self.current_command["timezone"], 'content': self.current_output.strip()})


    def parse_line(self, line: str) -> Dict:
        metadata_pattern = re.compile(r"(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[::badger authenticated from (?P<ips>.*)\]\[(?P<user>.*?)\]\[b-(?P<beacon_id>\d+?).*\]")
        watchlist_pattern = re.compile(r'(?P<timestamp>\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2} (?P<timezone>\w+))\s+\[Initial Access\]\s+b-(?P<beacon_id>\d+)\\\\[A-Z0-9]+\s+\((?P<user>.+?)\)\s+from\s+(?P<ips>.+?)\s+\[(?P<num1>\d+)->(?P<num2>\d+)\]')
        input_pattern = re.compile(r"^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[input\] (?P<operator>\w+) => (?P<command>.+)")
        output_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) (?P<content>\[sent \d+ bytes\])')
        upload_pattern = re.compile(r"(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[UPLOAD\] (?P<content>Host: (?P<host>.*) \| File: (?P<file>.*) \| MD5: (?P<md5>[a-f0-9]{32}))")
        access_denied_pattern = re.compile(r"^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) (?P<content>Access denied \(.+\): \[(?P<beacon_id>b-\d+) .+\])")
        http_request_pattern = re.compile(r"(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \n")
        http2_log_patter = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+))\s+\[\+\] b-(?P<id>\d+)\s+.*: \[(?P<ips>.*)\]')
        
        # metadata_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[::badger authenticated from (?P<ips>.*)\]\[(?P<user>.*?)\]\[b-(?P<beacon>\d+?).*\]')
        # input_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[input\] (?P<operator>.*?) => (?P<command>.*)')
        # output_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[(?P<content>sent \d+ bytes\]')
        # # output_pattern = re.compile(r'\[\*\] (?P<output>.*)')
        # http_log_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} UTC)\s+\[\+\] Verb: (?P<verb>\w+)\s+\[\+\] Remote Address: (?P<remote_address>[\d\.]+:\d+)\s+\[\+\] Request URI: (?P<request_uri>.*)')
        # http2_log_patter = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+))\s+\[\+\] b-(?P<id>\d+)\s+.*: \[(?P<ips>.*)\]')
        # watchlist_pattern = re.compile(r'(?P<Date>\d{2}-\d{2}-\d{4})\s+(?P<Time>\d{2}:\d{2}:\d{2})\s+(?P<TimeZone>\w+)\s+\[Initial\ Access\]\s+b-(?P<Identifier>\d+)\\\\[A-Z0-9]+\s+\((?P<HostUser>.+)\)\s+from\s+(?P<IPs>.+)\s+\[(?P<Num1>\d+)->(?P<Num2>\d+)\]')
        # upload_log_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[UPLOAD\] (?P<content>Host: (?P<host>.*) \| File: (?P<file_name>.*) \| MD5: (?P<md5>[a-f0-9]{32}))')
        # deauth_log_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) (?P<message>.*) \((?P<name>\w+)\): \[b-(?P<id>\d+).*\]\s+\[\+\] Verb: (?P<verb>\w+)\s+\[\+\] Remote Address: (?P<remote_address>[\d\.]+):\d+\s+\[\+\] Request URI: (?P<request_uri>.*)')
      

        metadata_match = metadata_pattern.match(line)
        watchlist_match = watchlist_pattern.match(line)
        input_match = input_pattern.match(line)
        output_match = output_pattern.match(line)
        upload_match = upload_pattern.match(line)
        access_denied_match = access_denied_pattern.match(line)
        http_request_match = http_request_pattern.match(line)
        http2_log_match = http2_log_patter.match(line)
        
        if metadata_match:
            return {
                'type': 'metadata',
                'timestamp': self.parse_timestamp(metadata_match.group('timestamp')),
                'timezone': metadata_match.group('timezone'),
                'ip': extract_ips(metadata_match.group('ips'))[-1],
                'ip_ext': extract_ips(metadata_match.group('ips'))[0],
                'user': metadata_match.group('user'),
                # 'id': metadata_match.group('beacon_id')
            }
        elif watchlist_match:
            return {
                'type': 'metadata',
                'timestamp': self.parse_timestamp(watchlist_match.group('timestamp')),
                'timezone': watchlist_match.group('timezone'),
                'ip': extract_ips(watchlist_match.group('ips'))[-1],
                'ip_ext': extract_ips(watchlist_match.group('ips'))[0],
                'user': watchlist_match.group('user'),
                # 'id': watchlist_match.group('id')
            }
        elif input_match:
            return {
                'type': 'input',
                'timestamp': self.parse_timestamp(input_match.group('timestamp')),
                'timezone': input_match.group('timezone'),
                'operator': input_match.group('operator'),
                'content': input_match.group('command')
            }
        elif output_match:
            return {
                'type': 'output',
                'timestamp': self.parse_timestamp(output_match.group('timestamp')),
                'timezone': output_match.group('timezone'),
                'content': output_match.group('content')
                # 'bytes': output_match.group('bytes'),
            }
        elif upload_match:
            return {
                'type': 'indicator',
                'timestamp': self.parse_timestamp(upload_match.group('timestamp')),
                'timezone': upload_match.group('timezone'),
                'content': upload_match.group('content')
                # 'host': upload_match.group('host'),
                # 'file': upload_match.group('file'),
                # 'md5': upload_match.group('md5'),
            }
        elif access_denied_match:
            return {
                'type': 'access_denied',
                'timestamp': self.parse_timestamp(access_denied_match.group('timestamp')),
                'timezone': access_denied_match.group('timezone'),
                'content': access_denied_match.group('content'),
                # 'beacon_id': access_denied_match.group('beacon_id')
            }
        elif http_request_match:
            return {
                'type': 'http_request',
                'timestamp': self.parse_timestamp(http_request_match.group('timestamp')),
                'timezone': http_request_match.group('timezone'),
                'content': http_request_match.group('content')
            }
        elif http2_log_match:
            return {
                'type': 'http_request',
                'timestamp': self.parse_timestamp(http2_log_match.group('timestamp')),
                'timezone': http2_log_match.group('timezone'),
                'content': http2_log_match.group('content')
            }
        return None
    

    def store_entry_to_db(self, entry_data: Dict):
        entry_type = EntryType[entry_data['type']]
        entry_data['type'] = entry_type
        try:
            existing_entry = self.session.query(Entry).filter_by(
                timestamp=entry_data['timestamp'],
                timezone=entry_data['timezone'],
                type=entry_type,
            ).one_or_none()

            if existing_entry is None:
                entry = Entry(**entry_data)
                self.session.add(entry)
            else:
                # Update the existing entry
                existing_entry.ttp = entry_data.get('ttp')
                existing_entry.operator = entry_data.get('operator')
                existing_entry.content = entry_data.get('content')
                self.session.add(existing_entry)

            self.session.commit()
        except Exception as e:
            self.session.rollback()
            print(f"Failed to insert log entry: {e}")

    def store_beacon_to_db(self, metadata: Dict):
        metadata.pop('type', None)
        try:
            existing_beacon = self.session.query(Beacon).filter_by(
                ip=metadata['ip'],
                user=metadata['user'],
                timestamp=metadata['timestamp']
            ).one_or_none()

            if existing_beacon is None:
                beacon = Beacon(**metadata)
                self.session.add(beacon)
            else:
                # Update the existing beacon via **metadata
                existing_beacon.timestamp = metadata['timestamp']
                existing_beacon.ip = metadata['ip']
                existing_beacon.ip_ext = metadata['ip_ext']
                existing_beacon.user = metadata['user']
                # existing_beacon.hostname = metadata['computer']
                # existing_beacon.process = metadata['process']
                # existing_beacon.pid = metadata['pid']
                # existing_beacon.os = metadata['os']
                # existing_beacon.version = metadata['version']
                # existing_beacon.build = metadata['build']
                # existing_beacon.arch = metadata['arch']
                self.session.add(existing_beacon)

            self.session.commit()
        except Exception as e:
            self.session.rollback()
            print(f"Failed to insert or update beacon: {e}")
