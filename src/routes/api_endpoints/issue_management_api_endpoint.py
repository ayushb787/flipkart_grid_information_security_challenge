from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import get_raw_db, get_db

from src.crud.api_crud import create_api, get_apis, create_log, get_logs
from src.schemas.api_schemas import APIInventoryCreate, APIInventory, SecurityLogCreate, SecurityLog
from ...db.alchemy import SessionLocal
from ...models.api_models import SecurityIssue
from ...utils.owasp_scanner import run_all_security_tests

router = APIRouter()


@router.put("/issues/{issue_id}/status")
async def update_issue_status(issue_id: int, status: str):
    """
    Update the status of a security issue by its id.
    """
    session = SessionLocal()
    try:
        issue = session.query(SecurityIssue).filter(SecurityIssue.id == issue_id).first()
        if not issue:
            raise HTTPException(status_code=404, detail="Issue not found")

        if status not in ["open", "closed"]:
            raise HTTPException(status_code=400, detail="Status must be 'open' or 'closed'")

        issue.status = status
        session.commit()
        return {"message": "Issue status updated successfully."}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

