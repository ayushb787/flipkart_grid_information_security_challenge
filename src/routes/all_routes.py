"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
from fastapi import APIRouter
from src.owasp_tests.owsap_main import router as owsap
from src.routes.api_endpoints.curd_api_endpoints import router as main_page
from src.routes.api_endpoints.owasp_scanning_api_endpoints import router as testing
from src.routes.api_endpoints.issue_management_api_endpoint import router as issue_management

router = APIRouter()

router.include_router(main_page)
router.include_router(testing)
router.include_router(issue_management)
router.include_router(owsap)