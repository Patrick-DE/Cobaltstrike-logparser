from datetime import datetime
import time
from typing import Dict, List, final

import sqlalchemy
from sqlalchemy.future import select
from sqlalchemy.future.engine import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import exc, update, delete, text, or_
from sqlalchemy.sql.expression import bindparam

from sqlite_model import *
from utils import log

SESSION = None

def init_db(db_path, debug):
    global SESSION
    try:
        engine = create_engine("sqlite:///"+db_path,echo=debug)
    except Exception as ex:
        log(f"Please provide a valid DB path: {ex}", "e")

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
        records = session.execute(select(cls).where(cls.id == id))
        results = records.scalars().first()
        return results
    except Exception as ex:
        log(f"get_element_by_id() Failed: {ex}", "e")
    finally:
        session.close()


def get_all_elements(cls):
    session = SESSION()
    rec =[]
    try:
        records = session.execute(select(cls))
        results = records.unique().scalars().fetchall()
        return results
    except Exception as ex:
        log(f"get_all_elements() Failed: {ex}", "e")
    finally:
        session.close()


def update_element(cls, **kwargs):
    session = SESSION()
    try:
        session.execute(
            update(cls).
            where(cls.id == kwargs["id"]).
            values(kwargs)
            )
        session.commit()
    except exc.IntegrityError:
        pass
    except Exception as ex:
        log(f"update_element() Failed: {ex}", "e")
    finally:
        session.close()

    return get_element_by_id(cls, kwargs["id"])


def delete_element(cls, id):
    session = SESSION()
    try:
        session.execute(delete(cls).where(cls.id == id))
        session.commit()
    except Exception as ex:
        log(f"delete_element() Failed: {ex}", "e")
    finally:
        session.close()


def get_element_by_values(cls, **kwargs):
    """
    Get one element of type CLS (generic) where values match
    """
    session = SESSION()
    bindTo = []
    try:
        #remove externalIP because beacons can connect to beacons ..
        kwargs.pop('ip_ext', None)

        for key, value in kwargs.items():
            bindTo.append(f"{ str(key) }=:{ str(key) }")

        qry = str(" and ".join(bindTo))
        query = f"SELECT * FROM {cls.__tablename__} WHERE {qry}"
        records = session.execute(text(query).bindparams(**kwargs))
        result = records.scalar()
        return result
    except Exception as ex:
        log(f"get_element_by_values() Failed: {ex}", "e")
    finally:
        session.close()


def create_element(cls, **kwargs):
    elem = get_element_by_values(cls, **kwargs)
    if elem:
        return elem

    session = SESSION()
    try:
        # if beacon is unknown drop id so it auto generates one
        if "id" in kwargs and kwargs["id"] == '':
            kwargs.pop("id")

        record = cls()
        for k, v in kwargs.items():
            setattr(record, k, v)

        session.add(record)
        session.commit()
        return record.id
    except exc.IntegrityError:
        elem = get_element_by_id(cls, kwargs["id"])
        return elem.id
    except Exception as ex:
        log(f"create_element({cls}) Failed: {ex}", "e")
    except sqlalchemy.sqlite3.OperationalError as ex:
        log(f"create_element({cls}) Failed: Database busy! Retrying..{ex}", "w")
        time.sleep(1)
        create_element(cls, **kwargs)
    finally:
        session.close()

# =========================
# =========BEACONS=========
# =========================
def get_last_entry_of_beacon(id):
    session = SESSION()
    record = None
    try:
        records: Entry = session.execute(select(Entry).where(Entry.parent_id == id ).order_by(Entry.timestamp.desc()))
        return records.scalars().first()
    except Exception as ex:
        log(f"get_last_entry_of_beacon() Failed: {ex}", "e")
    finally:
        session.close()


def get_first_metadata_entry_of_beacon(id):
    session = SESSION()
    try:
        records: Entry = session.execute(select(Entry).where(Entry.parent_id == id ).where(Entry.type == EntryType.metadata))
        result = records.scalars().first()
        return result
    except Exception as ex:
        log(f"get_first_metadata_entry_of_beacon() Failed: {ex}", "e")
    finally:
        session.close()


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


def get_all_entries_filtered(filter: EntryType) -> List:
    session = SESSION()
    try:
        records: Entry = session.execute(select(Entry).where(Entry.type == filter).order_by(Entry.timestamp.asc()))
        result = records.unique().scalars().fetchall()
        return result
    except Exception as ex:
        log(f"get_all_entries() Failed: {ex}", "e")
    finally:
        session.close()


def remove_clutter():
    """This function removes the following entries from the DB:
    - keylogger output
    - sleep commands issues by the operator
    - BeaconBot responses
    - Screenshot output
    https://docs.sqlalchemy.org/en/14/core/expression_api.html"""
    session = SESSION()
    try:
        entries = session.query(Entry).filter(
            or_(
                Entry.content.contains('> sleep'),
                Entry.content.contains('> exit'),
                Entry.content.contains('beacon to exit'),
                Entry.content.contains('beacon to sleep'),
                Entry.content.contains('beacon to list'),
                Entry.content.contains('beacon to back'),
                Entry.content.contains('to become interactive'),
                Entry.content.contains('beacon queue'),
                Entry.content.like('clear'),
                Entry.content.like('jobs'),
                Entry.content.contains('received keystrokes'),
                Entry.content.contains('<BeaconBot>'),
                Entry.content.contains('beacon is late'),
                Entry.content.contains('received screenshot'),
            ))
        entries.delete(synchronize_session=False)
        session.commit()
    except Exception as ex:
        log(f"get_all_entries() Failed: {ex}", "e")
    finally:
        session.close()


def compare_dates():
    """
    Get one element of type CLS (generic) where values match
    """
    session = SESSION()
    try:
        date = datetime.strptime("211124 09:49:52", '%y%m%d %H:%M:%S')
        records: sqlalchemy.engine.result.ChunkedIteratorResult = session.execute(select(Entry).where(Entry.type == EntryType.download).where(Entry.timestamp == date))
        results = records.unique().scalars().fetchall()
        return results
    except Exception as ex:
        log(f"get_element_by_values() Failed: {ex}", "e")
    finally:
        session.close()


def get_upload_entries():
    """
    Get one element of type CLS (generic) where values match
    """
    session = SESSION()
    try:
        records = session.execute(select(Entry).filter(
            or_(
                Entry.content.contains('Uploading beaconloader:'),
                Entry.content.contains('Uploading payload file:'),
                Entry.content.contains('Tasked beacon to upload'),
                Entry.type == EntryType.indicator
            )
        ))
        results = records.unique().scalars().fetchall()
        return results
    except Exception as ex:
        log(f"get_element_by_values() Failed: {ex}", "e")
    finally:
        session.close()