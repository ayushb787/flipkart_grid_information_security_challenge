from sqlalchemy import text, distinct
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload, selectinload
from src.models.api_models import APIInventory, SecurityIssue, SecurityTestResult
from src.schemas.api_schemas import APIInventoryCreate
from src.utils.owasp_scanner import run_all_security_tests


def get_api(db: Session, api_id: int):
    return db.query(APIInventory).filter(APIInventory.id == api_id).first()


def get_apis(db: Session, limit: int = 100):
    return db.query(APIInventory).options(joinedload(APIInventory.security_test_results)).limit(
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

    await run_all_security_tests(api_inventory_id=db_api.id, endpoint=db_api.url)

    return db_api


def count_unique_apis(db: Session):
    return db.query(APIInventory).distinct(APIInventory.id).count()


def count_open_issues(db: Session):
    return db.query(SecurityIssue).filter(SecurityIssue.status == 'open').count()


def count_closed_issues(db: Session):
    return db.query(SecurityIssue).filter(SecurityIssue.status == 'closed').count()


def count_total_apis(db: Session):
    return db.query(SecurityTestResult).count()


def count_high_severity_issues(db: Session):
    return db.query(SecurityIssue).filter(SecurityIssue.severity == 'High').count()


def count_medium_severity_issues(db: Session):
    return db.query(SecurityIssue).filter(SecurityIssue.severity == 'Medium').count()


def count_low_severity_issues(db: Session):
    return db.query(SecurityIssue).filter(SecurityIssue.severity == 'Low').count()
