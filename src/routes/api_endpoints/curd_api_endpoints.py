from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from .. import get_raw_db, get_db

from src.crud.api_crud import create_api, get_apis
from src.schemas.api_schemas import APIInventoryCreate, APIInventory
from ...utils.owasp_scanner import run_all_security_tests

router = APIRouter()


# Endpoint to discover a new API and create its record
@router.post("/apis/discover", response_model=APIInventory,
             summary="Discover a New API",
             description="Create a new API record in the inventory by providing its name and URL.")
async def discover_api(api: APIInventoryCreate, db: Session = Depends(get_db)):
    return await create_api(db=db, api=api)


# Endpoint to get a list of all APIs
@router.get("/apis", response_model=list[APIInventory],
            summary="Get All APIs",
            description="Retrieve a list of all registered APIs in the inventory with pagination support.")
def read_apis(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return get_apis(db=db, skip=skip, limit=limit)
