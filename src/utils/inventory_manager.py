from sqlalchemy.orm import Session
from src.crud.api_crud import create_api, get_apis
from src.schemas.api_schemas import APIInventoryCreate

def discover_api(db: Session, api: APIInventoryCreate):
    return create_api(db=db, api=api)

def get_api_list(db: Session, skip: int = 0, limit: int = 100):
    return get_apis(db=db, skip=skip, limit=limit)
