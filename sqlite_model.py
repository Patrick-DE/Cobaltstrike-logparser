from sqlalchemy import Column, DateTime, Integer, String, Enum
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql.schema import ForeignKey

import enum
class EntryType(enum.Enum):
      metadata = 1
      input = 2
      task = 3
      checkin = 4
      output = 5
      note = 6
      error = 7
      indicator = 8


Base = declarative_base()

class Beacon(Base):
      """
      Table definition for the SQLite DB
      """
      __tablename__ = "beacon"
      id = Column(Integer, primary_key= True)
      ip = Column(String, unique=True)
      ip_ext = Column(String, nullable=True)
      hostname = Column(String, nullable=True)
      user =  Column(String, nullable=True)
      process = Column(String, nullable=True)
      pid = Column(Integer, nullable=True)
      joined = Column(DateTime, nullable=True)
      exited = Column(DateTime, nullable=True)
      
class Entry(Base):
      """
      Table definition for the SQLite DB
      """
      __tablename__ = "entry"
      id = Column(Integer, primary_key = True)
      timestamp = Column(DateTime)
      timezone = Column(String)
      type = Column(Enum(EntryType))
      content = Column(String)
      parent_id = Column(Integer, ForeignKey('beacon.id'))