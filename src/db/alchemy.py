import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from loguru import logger
from src.db.base import Base
from src.models.api_models import APIInventory, SecurityLog

DBSession: sessionmaker = None

class settings:
    PROJECT_NAME: str = "flipkart_grid_information_security_challenge"
    POSTGRES_USER: str = os.getenv("POSTGRES_USER")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD")
    POSTGRES_SERVER: str = os.getenv("POSTGRES_SERVER", "localhost")
    POSTGRES_PORT: str = os.getenv("POSTGRES_PORT", 5432)
    POSTGRES_DB: str = os.getenv("POSTGRES_DB")
    DATABASE_URL = f"postgresql+psycopg2://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_SERVER}:{POSTGRES_PORT}/{POSTGRES_DB}"

settings = settings()

engine = create_engine(settings.DATABASE_URL, connect_args={'connect_timeout': 2}, pool_size=0, max_overflow=-1,
                       pool_recycle=3600)
try:
    Base.metadata.create_all(bind=engine)  # Create tables
    logger.info("Database connected and tables created successfully")
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
except Exception as e:
    logger.error("Database Connection Error - {}".format(e))

def init_db():
    Base.metadata.create_all(bind=engine)
