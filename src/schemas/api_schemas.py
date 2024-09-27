"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional


class SecurityTestResultSchema(BaseModel):
    id: int
    api_inventory_id: int
    endpoint: str
    scan_timestamp: datetime
    broken_auth: Optional[dict] = None
    bola: Optional[dict] = None
    excessive_data_exposure: Optional[dict] = None
    rate_limiting: Optional[dict] = None
    function_auth: Optional[dict] = None
    mass_assignment: Optional[dict] = None
    security_misconfig: Optional[dict] = None
    injection: Optional[List[dict]] = None
    asset_management: Optional[dict] = None
    logging_monitoring: Optional[dict] = None

    class Config:
        from_attributes = True


class APIInventoryBase(BaseModel):
    name: str
    url: str


class APIInventoryCreate(APIInventoryBase):
    pass


class APIInventory(APIInventoryBase):
    id: int
    last_scanned: Optional[datetime] = None
    security_test_results: List[SecurityTestResultSchema] = []

    class Config:
        orm_mode = True


class SecurityIssueBase(BaseModel):
    endpoint: str
    issue_description: str
    severity: str
    status: str
    detected_time: datetime


class SecurityIssue(SecurityIssueBase):
    id: int
    api_inventory_id: int

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    is_active: bool

    class Config:
        orm_mode = True
