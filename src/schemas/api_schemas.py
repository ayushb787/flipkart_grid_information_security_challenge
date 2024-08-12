from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional

class SecurityLogBase(BaseModel):
    issue: str
    severity: str

class SecurityLogCreate(SecurityLogBase):
    pass

class SecurityLog(SecurityLogBase):
    id: int
    api_id: int
    detected_on: datetime

    class Config:
        from_attributes = True  # Updated from orm_mode

class APIInventoryBase(BaseModel):
    name: str
    url: str

class APIInventoryCreate(APIInventoryBase):
    pass

class APIInventory(APIInventoryBase):
    id: int
    last_scanned: Optional[datetime] = None
    logs: List[SecurityLog] = []

    class Config:
        from_attributes = True  # Updated from orm_mode
