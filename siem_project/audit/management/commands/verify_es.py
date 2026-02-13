from django.core.management.base import BaseCommand
from audit.models import Transaction
from audit.logger import audit_logger
from django.conf import settings
from elasticsearch import Elasticsearch
import time

class Command(BaseCommand):
    help = 'Verify Elasticsearch synchronization for Transactions'

    def handle(self, *args, **options):
        self.stdout.write("--- Starting ES Verification ---")
        
        # 1. Create Transaction
        acc_num = f"CMD-ACC-{int(time.time())}"
        self.stdout.write(f"Creating transaction: {acc_num}")
        
        t = Transaction.objects.create(
            account_number=acc_num,
            amount=9999.99,
            transaction_type="CMD_TEST",
            location="Command Line"
        )
        self.stdout.write(f"Transaction created: {t}")
        
        self.stdout.write("Waiting 3 seconds for async sync...")
        time.sleep(3)
        
        # 2. Query ES
        es = Elasticsearch(
            hosts=settings.ELASTICSEARCH_HOSTS,
            verify_certs=False
        )
        
        index_name = settings.ELASTICSEARCH_INDEX
        self.stdout.write(f"Querying Index: {index_name}")
        
        # Check for transaction
        res_trans = es.search(index=index_name, query={
             "match": {"transaction_data.account_number": acc_num}
        }, size=1)
        
        if res_trans['hits']['hits']:
            source = res_trans['hits']['hits'][0]['_source']
            self.stdout.write(self.style.SUCCESS(f"[OK] Transaction found in ES! Amount: {source.get('transaction_data', {}).get('amount')}"))
        else:
            self.stdout.write(self.style.ERROR("[FAIL] Transaction NOT found in ES."))
