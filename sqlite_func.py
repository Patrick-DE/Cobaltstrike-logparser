from datetime import datetime
from typing import final

import sqlalchemy
from sqlalchemy.future import select
from sqlalchemy.future.engine import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import exc, update, delete

from sqlite_model import *
from utils import log

SESSION = None

def init_db(db_path, debug):
    global SESSION
    engine = create_engine("sqlite:///"+db_path,echo=debug)

    SESSION = sessionmaker(engine)
    Base.metadata.create_all(engine)

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
        log(f"get_beacon() Failed: {ex}", "e")
    finally:
        session.close()

    return record


def get_beacon_by_id(id):
    session = SESSION()
    record = None
    try:
        records: Beacon = session.execute(select(Beacon).where(Beacon.id == id))
        record = records.scalars().first()
    except Exception as ex:
        log(f"get_beacon() Failed: {ex}", "e")
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
        log(f"add_beacon() Failed: {ex}", "e")
    finally:
        session.close()

    return get_beacon_by_ip(ip)


def get_all_beacons():
    session = SESSION()
    rec = []
    try:
        records: Beacon = session.execute(select(Beacon))
        for record in records.scalars():
            rec.append(record)
    except Exception as ex:
        log(f"get_all_beacons() Failed: {ex}", "e")
    finally:
        session.close()

    return rec


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
        log(f"add_beacon() Failed: {ex}", "e")
    finally:
        session.close()

    return get_beacon_by_id(id)

# =========================
# ==========ENTRY==========
# =========================

def get_entry_by_id(id):
    session = SESSION()
    record = None
    try:
        records: Entry = session.execute(select(Entry).where(Entry.id == id))
        record = records.scalars().first()
    except Exception as ex:
        log(f"get_entry() Failed: {ex}", "e")
    finally:
        session.close()

    return record


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
        log(f"get_entry() Failed: {ex}", "e")
    finally:
        session.close()

    return record


def get_all_entries_of_beacon(id):
    session = SESSION()
    rec = []
    try:
        records: Entry = session.execute(select(Entry).where(Entry.parent_id == id))
        for record in records.scalars():
            rec.append(record)
    except Exception as ex:
        log(f"get_entry() Failed: {ex}", "e")
    finally:
        session.close()

    return rec


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
    res = None
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
        log(f"add_entry() Failed: {ex}", "e")
    finally:
        session.close()

    return get_entry_by_param(timestamp, timezone, type, content)


def get_all_entries():
    session = SESSION()
    rec = None
    try:
        records: Entry = session.execute(
            select(Entry).order_by(Entry.ip.desc())
        )
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
        log(f"get_entry() Failed: {ex}", "e")
    finally:
        session.close()

    return record


def update_entry(id, values):
    session = SESSION()
    try:
        session.execute(
            update(Entry).
            where(Entry.id == id).
            values(values)
            )
        session.commit()
    except exc.IntegrityError:
        pass
    except Exception as ex:
        log(f"add_beacon() Failed: {ex}", "e")
    finally:
        session.close()

    return get_entry_by_id(id)


def delete_entry(id):
    session = SESSION()
    record = None
    try:
        session.execute(delete(Entry).where(Entry.id == id))
        session.commit()
    except Exception as ex:
        log(f"get_entry() Failed: {ex}", "e")
    finally:
        session.close()

    return record