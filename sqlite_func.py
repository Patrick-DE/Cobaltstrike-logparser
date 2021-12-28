from datetime import datetime
import sys
from typing import Dict, List, final

import sqlalchemy
from sqlalchemy.future import select
from sqlalchemy.future.engine import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import exc, update, delete, text
from sqlalchemy.sql.expression import bindparam

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
        records = session.execute(select(cls))
        for record in records.unique().scalars():
            rec.append(record)

        return rec
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
    record = None
    bindTo = []
    try:
        #remove them because they cant be searched ..
        kwargs.pop('joined', None)
        kwargs.pop('exited', None)

        for key, value in kwargs.items():
            bindTo.append(f"{ str(key) }=:{ str(key) }")

        qry = str(" and ".join(bindTo))
        query = f"SELECT * FROM {cls.__tablename__} WHERE {qry}"
        records = session.execute(text(query).bindparams(**kwargs))
        record = records.scalars().first()
    except Exception as ex:
        log(f"get_element_by_values() Failed: {ex}", "e")
    finally:
        session.close()

    return record


def create_element(cls, **kwargs):
    session = SESSION()
    try:
        elem = get_element_by_values(cls, **kwargs)
        if elem:
            return elem

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
    record = None
    try:
        records: Entry = session.execute(select(Entry).where(Entry.parent_id == id ).where(Entry.type == EntryType.metadata))
        record = records.scalars().first()
        return record
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
