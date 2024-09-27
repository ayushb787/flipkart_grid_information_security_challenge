"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
from typing import List
from fastapi import APIRouter, HTTPException, Depends
from src.schemas.api_schemas import SecurityIssue as SecurityIssueSchema
from ...db.alchemy import SessionLocal
from src.models.api_models import SecurityIssue
from src.authorization.security import get_current_user

router = APIRouter()


@router.put("/issues/{api_inventory_id}/status")
async def update_issue_status(api_inventory_id: int, status: str, token: str = Depends(get_current_user)):
    """
    Update the status of a security issue by its id.
    """
    session = SessionLocal()
    try:
        issue = session.query(SecurityIssue).filter(SecurityIssue.api_inventory_id == api_inventory_id).first()
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


@router.get("/issues/{api_inventory_id}", response_model=List[SecurityIssueSchema])
async def get_issues_by_inventory_id(api_inventory_id: int, token: str = Depends(get_current_user)):
    """
    Get all security issues related to a given API inventory ID.
    """
    session = SessionLocal()
    try:
        issues = session.query(SecurityIssue).filter(SecurityIssue.api_inventory_id == api_inventory_id).all()

        if not issues:
            raise HTTPException(status_code=404, detail="No issues found for the given API inventory ID.")

        return [SecurityIssueSchema.from_orm(issue) for issue in issues]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()
