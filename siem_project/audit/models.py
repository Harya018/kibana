from django.db import models

# Create your models here.
class AuditLog(models.Model):
    event_type = models.CharField(max_length=50)
    username = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    severity = models.CharField(max_length=10)
    timestamp = models.DateTimeField(auto_now_add=True)
