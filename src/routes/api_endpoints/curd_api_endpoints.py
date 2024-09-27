"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from .. import get_db
from src.schemas.api_schemas import APIInventoryCreate, APIInventory
from src.authorization.security import get_current_user
from src.crud.api_crud import (
    create_api,
    get_apis,
    get_unique_apis,
    count_unique_apis,
    count_open_issues,
    count_closed_issues,
    count_total_apis,
    count_high_severity_issues,
    count_low_severity_issues,
    count_medium_severity_issues
)

router = APIRouter()


@router.post("/apis/discover", response_model=APIInventory,
             summary="Discover a New API",
             description="Create a new API record in the inventory by providing its name and URL.")
async def discover_api(api: APIInventoryCreate, db: Session = Depends(get_db), token: str = Depends(get_current_user)):
    return await create_api(db=db, api=api)


@router.get("/apis", response_model=list[APIInventory],
            summary="Get All APIs",
            description="Retrieve a list of all registered APIs in the inventory with pagination support.")
def read_apis(limit: int = 100, db: Session = Depends(get_db), token: str = Depends(get_current_user)):
    return get_apis(db=db, limit=limit)


@router.get("/unique-apis")
def read_unique_apis(db: Session = Depends(get_db), token: str = Depends(get_current_user)):
    return get_unique_apis(db)


@router.get("/dashboard", summary="Total APIs",
            description="Get the total number of APIs in the database.")
def total_apis(db: Session = Depends(get_db), token: str = Depends(get_current_user)):
    return {"total_apis": count_total_apis(db),
            "total_unique_apis": count_unique_apis(db),
            "total_closed_issues": count_closed_issues(db),
            "total_open_issues": count_open_issues(db),
            "total_high_severity_issues": count_high_severity_issues(db),
            "total_medium_severity_issues": count_medium_severity_issues(db),
            "total_low_severity_issues": count_low_severity_issues(db)}
