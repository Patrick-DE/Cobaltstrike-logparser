from dataclasses import dataclass
from typing import List, Dict
import yaml
import ipaddress

@dataclass
class Flags:
    case_insensitive: bool = True
    replacement: str = r"\1[REDACTED]"

@dataclass
class Pattern:
    pattern: str
    description: str

@dataclass
class Redactions:
    patterns: Dict[str, Pattern]
    flags: Flags

@dataclass
class CSPatterns:
    time: str
    ipv4: str
    date: str
    metadata: str
    input: str
    output: str
    task: str
    checkin: str
    received_output: str
    event: str
    download: str
    error: str
    job_registered: str
    job_completed: str
    indicator: str
    
@dataclass
class BRPatterns:
    time: str

@dataclass
class Parsing:
    cs: CSPatterns
    br: CSPatterns

@dataclass
class AndCommand:
    _and: List[str]

@dataclass
class Exclusions:
    internal: List[str]
    external: List[str]
    hostnames: List[str]
    commands: List[str|AndCommand]

@dataclass
class Config:
    exclusions: Exclusions
    # parsing: Parsing
    redactions: Redactions

# Initialize the global config with empty placeholders
config: Config = None

def unescape_pattern(pattern: str) -> str:
    """Unescape backslashes in the regex pattern."""
    return pattern.encode('utf-8').decode('unicode_escape')

def resolve_patterns(patterns: Dict[str, str]) -> Dict[str, str]:
    """Resolve references in composite patterns"""
    resolved = {}
    base_patterns = {
        'time': patterns['time'].strip(),
        'ipv4': patterns['ipv4'].strip(),
        'date': patterns['date'].strip()
    }
    
    for name, pattern in patterns.items():
        if isinstance(pattern, str) and '${cs.' in pattern:
            for base_name, base_pattern in base_patterns.items():
                pattern = pattern.strip()
                pattern = pattern.replace(f'${{cs.{base_name}}}', base_pattern)
            resolved[name] = pattern
        else:
            # Unescape base patterns as well
            resolved[name] = pattern
    return resolved


def load_config(filename: str) -> Config:
    """Load and process configuration from YAML file"""
    global config
    with open(filename) as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"[!] Failed to load configuration: {e}")
            config = None
            return
        
        # Clean and resolve pattern references
        if 'parsing' in data and 'cs' in data['parsing']:
            patterns = data['parsing']['cs']
            # Resolve patterns without adding extra escapes
            data['parsing']['cs'] = resolve_patterns(patterns)
            
    config = Config(
        exclusions=Exclusions(**data['exclusions']),
        # parsing=Parsing(
        #     cs=CSPatterns(**data['parsing']['cs']),
        #     br=BRPatterns(**data['parsing']['br'])
        # ),
        redactions=Redactions(
            patterns={k: Pattern(**v) for k, v in data['redactions']['patterns'].items()},
            flags=Flags(**data['redactions']['flags'])
        )
    )
    return config


def reload_config(filename: str) -> Config:
    """Reload configuration from file"""
    return load_config(filename)

def get_config() -> Config:
    """Get the current configuration"""
    return config

def is_ip_excluded(ip: str, excluded_ranges: List[str]) -> bool:
    """
    Check if IP is in any excluded range
    Args:
        ip: String IP address to check
        excluded_ranges: List of CIDR ranges as strings
    Returns:
        bool: True if IP is in any excluded range
    """
    try:
        for range in excluded_ranges:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(range):
                return True
        return False
    except ValueError as ex:
        print("[!] Invalid IP:" + ip + " : " + ex.strerror)
        return False