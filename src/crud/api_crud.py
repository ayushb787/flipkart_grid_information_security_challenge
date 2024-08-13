from sqlalchemy import text, distinct
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload, selectinload
from src.models.api_models import APIInventory
from src.schemas.api_schemas import APIInventoryCreate
from src.utils.owasp_scanner import run_all_security_tests


def get_api(db: Session, api_id: int):
    return db.query(APIInventory).filter(APIInventory.id == api_id).first()


def get_apis(db: Session, skip: int = 0, limit: int = 100):
    return db.query(APIInventory).options(joinedload(APIInventory.security_test_results)).offset(skip).limit(
        limit).all()

def get_unique_apis(db: Session):
    """
    Retrieve all unique API entries (id, name, url) from the APIInventory table.
    """
    unique_apis = db.query(
        distinct(APIInventory.id),
        APIInventory.name,
        APIInventory.url
    ).all()

    return [
        {"id": api[0], "name": api[1], "url": api[2]}
        for api in unique_apis
    ]

async def create_api(db: Session, api: APIInventoryCreate):
    # Check if the API already exists with the same name and URL
    existing_api = db.query(APIInventory).filter(
        APIInventory.name == api.name,
        APIInventory.url == api.url
    ).first()

    if existing_api:
        return existing_api

    db_api = APIInventory(name=api.name, url=api.url)
    db.add(db_api)
    db.commit()
    db.refresh(db_api)

    # Run all security tests for the created API
    await run_all_security_tests(api_inventory_id=db_api.id, endpoint=db_api.url)

    return db_api
