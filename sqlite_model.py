from sqlalchemy import Column, DateTime, Integer, String, Enum
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql.schema import ForeignKey
import re

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
      # custom attributes
      download = 9
      upload = 10
      events = 11


Base = declarative_base()

class Beacon(Base):
      """
      Table definition for the SQLite DB
      """
      __tablename__ = "beacon"
      id = Column(Integer, primary_key= True)
      ip = Column(String, unique=False)
      ip_ext = Column(String, nullable=True)
      hostname = Column(String, nullable=True)
      user =  Column(String, nullable=True)
      process = Column(String, nullable=True)
      pid = Column(Integer, nullable=True)
      date = Column(String, nullable=False)
      joined = Column(DateTime, nullable=True)
      exited = Column(DateTime, nullable=True)
      entries = relationship("Entry", back_populates="parent",lazy='joined', join_depth=1)

      def is_high_integrity(self):
            if "*" in self.user:
                  return True
            else:
                  return False
      
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
      parent = relationship("Beacon", back_populates="entries", lazy="joined", join_depth=1)

      #def __getattribute__(self, item):
      #      if item == "content" and self.type == EntryType.input:
      #            return re.sub(r"\s*<.*>\s*(.*)", "", self.content).group(1)

      def get_operator(self):
            if self.type == EntryType.input:
                  return self.content.split("<")[1].split(">")[0]
            return None

      def get_input(self):
            if self.type == EntryType.input or self.type == EntryType.task:
                  return re.sub(r"\s*<.*>\s*(.*)", r"\1", self.content)
            else:
                  raise ValueError("This function can only be called with EntryType.input or EntryType.task")

      def to_row(self):
            hostname, user, ip = "","",""
            if self.type == EntryType.input or self.type == EntryType.task:
                  content = self.get_input()
            else:
                  content = self.content

            date = self.timestamp.strftime("%d/%m/%y")
            time = self.timestamp.strftime("%H:%M")
            b = self.parent
            if b:
                  hostname, user, ip = b.hostname, b.user, b.ip
            return [date, time, hostname, content, user, ip]