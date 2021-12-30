# pattern to match process the logs
pattern_time = r"(?P<timestamp>(?:\d{2}\/*){2} (?:\d\d:*){3})\s(?P<timezone>\S+)\s"
pattern_line = pattern_time + r"\[(?P<type>\w+)\](?P<content>.*)"
pattern_ipv4 = r"(?P<ipv4>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"
pattern_date = r"\\(?P<date>\d{6})\\"
pattern_metadata = pattern_ipv4 + r"|(?:\w+:\s(.*?);)|(?P<beacon>\w+_\d+)"
pattern_download = pattern_time + pattern_ipv4 + r"\s\d+\s\d+\s.*?\s(?P<fname>.*)\t(?P<path>\b.*\b)"
pattern_events = pattern_time + r"(?P<content>.*?from\s(?P<user>\b.*\b\s*.*?)@"+ pattern_ipv4 +"\s\((?P<hostname>.*?)\))"

# IPRange to be excluded
exclude = []