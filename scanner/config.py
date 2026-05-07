import os
import logging
import yaml

def load_config():
    config_path = os.path.join(os.getcwd(), 'config.yaml')
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    return {}

CONFIG = load_config()
MS = CONFIG.get('mail_settings', {})

SENDER_EMAIL    = os.environ.get('SENDER_EMAIL',    MS.get('email',       ''))
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', MS.get('password',    ''))
SMTP_SERVER     = os.environ.get('SMTP_SERVER',     MS.get('smtp_server', 'smtp.gmail.com'))
SMTP_PORT       = int(os.environ.get('SMTP_PORT',   MS.get('smtp_port',   587)))
MAILGUN_API_KEY = os.environ.get('MAILGUN_API_KEY', MS.get('mailgun_api_key', ''))
MAILGUN_DOMAIN  = os.environ.get('MAILGUN_DOMAIN',  MS.get('mailgun_domain',  ''))

OUTPUT_DIR = os.path.join(os.getcwd(), 'outputs')
LOG_PATH   = os.path.join(OUTPUT_DIR, 'logs.txt')

os.makedirs(OUTPUT_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
