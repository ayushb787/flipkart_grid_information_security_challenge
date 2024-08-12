from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from .. import get_raw_db, get_db
from fastapi import FastAPI, BackgroundTasks
from src.crud.api_crud import create_api, get_apis, create_log, get_logs
from src.schemas.api_schemas import APIInventoryCreate, APIInventory, SecurityLogCreate, SecurityLog
from ...utils.owasp_scanner import run_all_security_tests

router = APIRouter()

@router.get("/run_security_tests")
async def run_security_tests(endpoint: str):
    """
    API endpoint to run all OWASP Top 10 security owasp_tests and return results as JSON.
    """
    results = await run_all_security_tests(endpoint)
    return results