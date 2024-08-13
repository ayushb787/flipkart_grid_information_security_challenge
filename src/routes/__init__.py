from loguru import logger as logging
from src.db.alchemy import engine, AsyncSessionLocal
from src.db.alchemy import SessionLocal
from sqlalchemy.ext.asyncio import AsyncSession

# In your database setup
async def get_async_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session

def get_db():
    db = SessionLocal()
    logging.info("get_db")
    try:
        logging.debug("yielding db")
        yield db
    finally:
        logging.debug("closing db")
        db.close()

def get_raw_db():
    db = engine.raw_connection()
    logging.info("get_db")
    try:
        logging.debug("yielding db")
        yield db
    finally:
        logging.debug("closing db")
        db.close()