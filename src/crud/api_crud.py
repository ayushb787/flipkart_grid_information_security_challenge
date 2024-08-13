from sqlalchemy import text
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


async def create_api(db: Session, api: APIInventoryCreate):
    db_api = APIInventory(name=api.name, url=api.url)
    db.add(db_api)
    db.commit()
    db.refresh(db_api)

    # Run all security tests for the created API
    await run_all_security_tests(api_inventory_id=db_api.id, endpoint=db_api.url)

    return db_api
