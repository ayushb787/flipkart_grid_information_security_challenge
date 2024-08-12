from fastapi import APIRouter

from src.routes.api_endpoints.curd_api_endpoints import router as main_page

from src.routes.api_endpoints.owasp_scanning_api_endpoints import router as testing

router = APIRouter()

router.include_router(main_page)
router.include_router(testing)