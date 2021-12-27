from datetime import datetime
import sys
from typing import Dict, List, final

import sqlalchemy
from sqlalchemy.future import select
from sqlalchemy.future.engine import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import exc, update, delete, or_, and_

from sqlite_model import *
from utils import log

SESSION = None

def init_db(db_path, debug):
    global SESSION
    engine = create_engine("sqlite:///"+db_path,echo=debug)

    SESSION = sessionmaker(engine)
    Base.metadata.create_all(engine)


# =========================
# =========GENERIC=========
# =========================
def get_element_by_id(cls, id):
    """
    Get row of type CLS (generic) with ID id
    """
    session = SESSION()
    record = None
    try:
        cls = getattr(sys.modules[__name__], cls)
        records = session.execute(select(cls).where(cls.id == id))
        record = records.scalars().first()
    except Exception as ex:
        log(f"get_element_by_id() Failed: {ex}", "e")
    finally:
        session.close()

    return record


def get_all_elements(cls):
    session = SESSION()
    rec =[]
    try:
        cls = getattr(sys.modules[__name__], cls)
        records = session.execute(select(cls))
        for record in records.scalars():
            rec.append(record)
    except Exception as ex:
        log(f"get_all_elements() Failed: {ex}", "e")
    finally:
        session.close()

    return rec


def update_element(cls, id, values):
    session = SESSION()
    try:
        cls = getattr(sys.modules[__name__], cls)
        session.execute(
            update(cls).
            where(cls.id == id).
            values(values)
            )
        session.commit()
    except exc.IntegrityError:
        pass
    except Exception as ex:
        log(f"update_element() Failed: {ex}", "e")
    finally:
        session.close()

    return get_element_by_id(cls, id)


def delete_element(cls, id):
    session = SESSION()
    try:
        cls = getattr(sys.modules[__name__], cls)
        session.execute(delete(cls).where(cls.id == id))
        session.commit()
    except Exception as ex:
        log(f"delete_element() Failed: {ex}", "e")
    finally:
        session.close()


def get_element_by_values(cls, values):
    """
    Get row of type CLS (generic) with ID id
    """
    session = SESSION()
    record = None
    try:
        # {
        # Entry.timestamp :row['timestamp'], 
        # Entry.timezone : row["timezone"],
        # Entry.type : row['type'],
        # Entry.content : row['content'],
        # Entry.parent_id : record.id
        # }
        cls = getattr(sys.modules[__name__], cls)
        records = session.execute(f"SELECT * FROM "+cls)
        record = records.scalars().first()
    except Exception as ex:
        log(f"get_element_by_values() Failed: {ex}", "e")
    finally:
        session.close()

    return record


# =========================
# =========BEACONS=========
# =========================
def get_beacon_by_ip(ip):
    session = SESSION()
    record = None
    try:
        records: Beacon = session.execute(select(Beacon).where(Beacon.ip == ip))
        record = records.scalars().first()
    except Exception as ex:
        log(f"get_beacon_by_ip() Failed: {ex}", "e")
    finally:
        session.close()

    return record


def create_beacon(ip, hostname=None):
    session = SESSION()
    try:
        record: Beacon = Beacon(
            ip = ip,
            hostname = hostname,
        )
        session.add(record)
        session.commit()
    except exc.IntegrityError:
        pass
    except Exception as ex:
        log(f"create_beacon() Failed: {ex}", "e")
    finally:
        session.close()

    return get_beacon_by_ip(ip)


def update_beacon(id, values):
    session = SESSION()
    try:
        session.execute(
            update(Beacon).
            where(Beacon.id == id).
            values(values)
            )
        session.commit()
    except exc.IntegrityError:
        pass
    except Exception as ex:
        log(f"update_beacon() Failed: {ex}", "e")
    finally:
        session.close()

    return get_element_by_id("Beacon", id)

# =========================
# ==========ENTRY==========
# =========================
def get_entry_by_param(timestamp, timezone, type, content):
    session = SESSION()
    record = None
    try:
        records: Entry = session.execute(
            select(Entry).
            where(Entry.timestamp == timestamp).
            where(Entry.timezone == timezone).
            where(Entry.type == type)
            )
        record = records.scalars().first()
    except Exception as ex:
        log(f"get_entry_by_param() Failed: {ex}", "e")
    finally:
        session.close()

    return record


def create_entry(timestamp, timezone, type, content, parent_id):
    """
    id = Column(Integer, primary_key = True)
    timestamp = Column(DateTime, unique=False, nullable=False)
    timezone = Column(String)
    type = Column(Enum(EntryType))
    content = Column(String, unique=False, nullable=False)
    parent_id = Column(Integer, ForeignKey('beacon.id'))
    """
    session = SESSION()
    res = []
    try:
        res = get_entry_by_param(timestamp, timezone, type, content)
        if res:
            return res 

        record: Entry = Entry(
            timestamp = timestamp,
            timezone = timezone,
            type = type,
            content = content,
            parent_id = parent_id,
        )
        session.add(record)
        session.commit()
    except Exception as ex:
        log(f"create_entry() Failed: {ex}", "e")
    finally:
        session.close()

    return get_entry_by_param(timestamp, timezone, type, content)


def get_all_entries_filtered(filter: EntryType) -> List:
    session = SESSION()
    rec = []
    try:
        records: Entry = session.execute((select(Entry).where(Entry.type == filter).order_by(Entry.timestamp.asc())))
        
        for record in records.scalars():
            rec.append(record)
    except Exception as ex:
        log(f"get_all_entries() Failed: {ex}", "e")
    finally:
        session.close()

    return rec


def get_first_metadata_entry_of_beacon(id):
    session = SESSION()
    record = None
    try:
        records: Entry = session.execute(select(Entry).where(Entry.parent_id == id ).where(Entry.type == EntryType.metadata))
        record = records.scalars().first()
    except Exception as ex:
        log(f"get_first_metadata_entry_of_beacon() Failed: {ex}", "e")
    finally:
        session.close()

    return record

