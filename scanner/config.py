import os
import logging

OUTPUT_DIR = os.path.join(os.getcwd(), 'outputs')
LOG_PATH   = os.path.join(OUTPUT_DIR, 'logs.txt')

os.makedirs(OUTPUT_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
