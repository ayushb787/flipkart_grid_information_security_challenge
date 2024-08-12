from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from .. import get_raw_db, get_db

from src.crud.api_crud import create_api, get_apis, create_log, get_logs
from src.schemas.api_schemas import APIInventoryCreate, APIInventory, SecurityLogCreate, SecurityLog
from ...utils.owasp_scanner import run_all_security_tests

router = APIRouter()


# Endpoint to discover a new API and create its record
@router.post("/apis/discover", response_model=APIInventory,
             summary="Discover a New API",
             description="Create a new API record in the inventory by providing its name and URL.")
def discover_api(api: APIInventoryCreate, db: Session = Depends(get_db)):
    return create_api(db=db, api=api)


# Endpoint to get a list of all APIs
@router.get("/apis", response_model=list[APIInventory],
            summary="Get All APIs",
            description="Retrieve a list of all registered APIs in the inventory with pagination support.")
def read_apis(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return get_apis(db=db, skip=skip, limit=limit)


# Endpoint to log security issues related to a specific API
@router.post("/apis/{api_id}/logs", response_model=SecurityLog,
             summary="Log Security Issue",
             description="Log a security issue for a specific API by its ID. Provide the issue description and severity level.")
def log_security_issue(api_id: int, log: SecurityLogCreate, db: Session = Depends(get_db)):
    return create_log(db=db, log=log, api_id=api_id)


# Endpoint to get logs for a specific API
@router.get("/apis/{api_id}/logs", response_model=list[SecurityLog],
            summary="Get API Logs",
            description="Retrieve all logged security issues for a specific API identified by its ID. Pagination is supported.")
def read_logs(api_id: int, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return get_logs(db=db, api_id=api_id, skip=skip, limit=limit)
