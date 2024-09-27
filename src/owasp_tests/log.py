"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
import logging
import os

if os.getcwd().split('/')[-1] == 'API':
        path = 'src/logs/scan.log'
else:
        path = 'src/logs/scan.log'


logger = logging.getLogger()
fh = logging.FileHandler(path)
logger.addHandler(fh)
logger.setLevel(logging.INFO)

#logging.basicConfig(filename=path, level=logging.INFO)