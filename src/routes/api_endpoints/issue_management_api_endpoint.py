from fastapi import APIRouter, HTTPException
from ...db.alchemy import SessionLocal
from ...models.api_models import SecurityIssue

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

