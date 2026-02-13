from django.test import TestCase
from .models import Transaction

class TransactionTestCase(TestCase):
    def test_fraud_flagging(self):
        """Transactions > 10000 should be flagged"""
        t1 = Transaction.objects.create(
            account_number="123", amount=5000, transaction_type="DEBIT", location="NY"
        )
        t2 = Transaction.objects.create(
            account_number="456", amount=15000, transaction_type="DEBIT", location="NY"
        )
        
        self.assertFalse(t1.is_flagged)
        self.assertTrue(t2.is_flagged)
        self.assertEqual(t2.flag_reason, "High Value Transaction (> 10000)")

    def test_transaction_creation(self):
        t = Transaction.objects.create(
            account_number="789", amount=100, transaction_type="Start", location="Test"
        )
        self.assertEqual(t.amount, 100)
