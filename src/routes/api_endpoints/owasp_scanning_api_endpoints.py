"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
from fastapi import APIRouter
from ...utils.owasp_scanner import run_all_security_tests

router = APIRouter()


@router.get("/run_security_tests")
async def run_security_tests(endpoint: str):
    """
    API endpoint to run all OWASP Top 10 security owasp_tests and return results as JSON.
    """
    results = await run_all_security_tests(endpoint)
    return results
