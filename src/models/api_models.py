from sqlalchemy import Column, Integer, String, JSON, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from src.db.alchemy import Base
from datetime import datetime
from sqlalchemy.sql import func

class APIInventory(Base):
    __tablename__ = "api_inventories"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    url = Column(String, index=True)
    last_scanned = Column(DateTime, default=datetime.utcnow)

    # Relationship to SecurityTestResult
    security_test_results = relationship("SecurityTestResult", back_populates="api_inventory")

class SecurityTestResult(Base):
    __tablename__ = 'security_test_results'

    id = Column(Integer, primary_key=True, index=True)
    api_inventory_id = Column(Integer, ForeignKey('api_inventories.id'))
    endpoint = Column(String, index=True)
    scan_timestamp = Column(DateTime(timezone=True), server_default=func.now())
    broken_auth = Column(JSON)
    bola = Column(JSON)
    excessive_data_exposure = Column(JSON)
    rate_limiting = Column(JSON)
    function_auth = Column(JSON)
    mass_assignment = Column(JSON)
    security_misconfig = Column(JSON)
    injection = Column(JSON)
    asset_management = Column(JSON)
    logging_monitoring = Column(JSON)

    # Relationship to APIInventory
    api_inventory = relationship("APIInventory", back_populates="security_test_results")

class SecurityIssue(Base):
    __tablename__ = 'security_issues'

    id = Column(Integer, primary_key=True, index=True)
    api_inventory_id = Column(Integer, ForeignKey('api_inventories.id'))
    endpoint = Column(String, index=True)
    issue_description = Column(String)
    severity = Column(String)
    status = Column(String, default="open")
    detected_time = Column(DateTime(timezone=True), server_default=func.now())
