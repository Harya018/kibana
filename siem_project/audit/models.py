from django.db import models

# Create your models here.
class AuditLog(models.Model):
    event_type = models.CharField(max_length=50)
    username = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    severity = models.CharField(max_length=10)
    timestamp = models.DateTimeField(auto_now_add=True)

class Transaction(models.Model):
    account_number = models.CharField(max_length=20)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_type = models.CharField(max_length=20) # e.g., 'DEBIT', 'CREDIT'
    timestamp = models.DateTimeField(auto_now_add=True)
    location = models.CharField(max_length=100)
    is_flagged = models.BooleanField(default=False)
    flag_reason = models.CharField(max_length=255, blank=True, null=True)

    def save(self, *args, **kwargs):
        # Basic fraud detection logic
        if self.amount > 10000:
            self.is_flagged = True
            self.flag_reason = "High Value Transaction (> 10000)"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.transaction_type} - {self.amount} - {self.is_flagged}"
