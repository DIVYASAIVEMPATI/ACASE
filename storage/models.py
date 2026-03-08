from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "acase.db"
engine = create_engine(f"sqlite:///{DB_PATH}")
Base = declarative_base()
Session = sessionmaker(bind=engine)

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    target = Column(String, nullable=False)
    finding_type = Column(String, nullable=False)
    evidence = Column(Text)
    risk_level = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(engine)

def save_finding(target, finding_type, evidence, risk_level):
    init_db()
    session = Session()
    f = Finding(target=target, finding_type=finding_type, evidence=evidence, risk_level=risk_level)
    session.add(f)
    session.commit()
    session.close()

def get_findings(target):
    init_db()
    session = Session()
    results = session.query(Finding).filter_by(target=target).all()
    session.close()
    return results
