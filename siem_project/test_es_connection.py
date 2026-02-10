import os
import django
import time

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "siem_project.settings")
django.setup()

from audit.logger import audit_logger
from django.conf import settings

print(f"Connecting to ES at: {settings.ELASTICSEARCH_HOSTS}")
print(f"Index: {settings.ELASTICSEARCH_INDEX}")

try:
    print("Sending test log...")
    audit_logger.info("Verification Log", extra={
        'event_type': 'VERIFY_CONNECTION',
        'username': 'admin_test',
        'ip_address': '127.0.0.1'
    })
    print("Log sent successfully (to buffer/ES).")
except Exception as e:
    print(f"FAILED to send log: {e}")
