from sqlalchemy.orm import Session, joinedload
from src.models.api_models import APIInventory, SecurityLog
from src.schemas.api_schemas import APIInventoryCreate, SecurityLogCreate

def get_api(db: Session, api_id: int):
    return db.query(APIInventory).filter(APIInventory.id == api_id).first()

def get_apis(db: Session, skip: int = 0, limit: int = 100):
    return db.query(APIInventory).options(joinedload(APIInventory.logs)).offset(skip).limit(limit).all()


def create_api(db: Session, api: APIInventoryCreate):
    db_api = APIInventory(name=api.name, url=api.url)
    db.add(db_api)
    db.commit()
    db.refresh(db_api)
    return db_api

def create_log(db: Session, log: SecurityLogCreate, api_id: int):
    db_log = SecurityLog(**log.dict(), api_id=api_id)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

def get_logs(db: Session, api_id: int, skip: int = 0, limit: int = 100):
    return db.query(SecurityLog).filter(SecurityLog.api_id == api_id).offset(skip).limit(limit).all()
