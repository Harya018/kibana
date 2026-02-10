import logging
from elasticsearch import Elasticsearch, ApiError
from django.conf import settings
from datetime import datetime, timezone

# Initialize ES client
es_client = Elasticsearch(
    hosts=settings.ELASTICSEARCH_HOSTS,
    api_key=settings.ELASTICSEARCH_API_KEY if settings.ELASTICSEARCH_API_KEY else None,
    verify_certs=False  # Disable for local dev; enable in prod
)

class ElasticsearchHandler(logging.Handler):
    def emit(self, record):
        try:
            log_entry = {
                'event_type': getattr(record, 'event_type', record.getMessage()),
                'username': getattr(record, 'username', 'unknown'),
                'ip_address': getattr(record, 'ip_address', 'unknown'),
                'severity': record.levelname,
                'timestamp': datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
                'message': record.getMessage()
            }
            es_client.index(index=settings.ELASTICSEARCH_INDEX, document=log_entry)
        except ApiError as e:
            # Fallback: Log to console if ES fails
            logging.error(f"Elasticsearch logging failed: {e}")
        except Exception as e:
            logging.error(f"Unexpected error in ES logging: {e}")

# Configure audit logger
audit_logger = logging.getLogger('audit')
audit_logger.addHandler(ElasticsearchHandler())
audit_logger.setLevel(logging.INFO)
