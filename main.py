import limiter
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from uvicorn import run
from src.routes.api_endpoints.auth_endpoints import router as auth_router
from src.routes.all_routes import router
from src.db.alchemy import Base, engine

app = FastAPI(
    title='Flipkart Grid Information Security Challenge'
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(router, prefix="/api", tags=["API"])


app.include_router(router)
Base.metadata.create_all(engine)

@app.get("/api/limited-endpoint")
@limiter.limit("5/minute")
async def limited_endpoint():
    return {"message": "This endpoint is rate-limited to 5 requests per minute"}


if __name__ == "__main__" or __name__ == "__FlipkartGridInformationSecurityChallenge__":
    run("main:app", host="0.0.0.0", port=7000, reload=True)
