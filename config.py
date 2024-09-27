"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
import os

class Config:
    DEBUG = os.getenv("DEBUG", False)

config = Config()
