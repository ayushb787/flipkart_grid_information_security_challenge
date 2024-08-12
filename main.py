from uvicorn import run
from src.routes.all_routes import router
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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
app.include_router(router)
Base.metadata.create_all(engine)
if __name__ == "__main__" or __name__ == "__FlipkartGridInformationSecurityChallenge__":
    run("main:app", host="0.0.0.0", port=7000, reload=True)
