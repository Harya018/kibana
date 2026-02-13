print(">>> AUDIT SIGNALS FILE LOADED <<<")

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings
from .models import AuditLog
from .logger import audit_logger  

def send_alert(subject, message, recipient_list=None):
    """Send email alert for high-severity events."""
    if not recipient_list:
        recipient_list = ['admin@example.com']  # Default; configure as needed
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipient_list,
            fail_silently=False,
        )
    except Exception as e:
        # Log alert failure
        audit_logger.error(f"Failed to send alert email: {e}")


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    ip = request.META.get("REMOTE_ADDR")

    # 1️⃣ DB audit (unchanged)
    AuditLog.objects.create(
        event_type="LOGIN_SUCCESS",
        username=user.username,
        ip_address=ip,
        severity="LOW"
    )

    # 2️⃣ ES log (NEW)
    audit_logger.info("User login successful", extra={
        'event_type': 'LOGIN_SUCCESS',
        'username': user.username,
        'ip_address': ip
    })


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    ip = request.META.get("REMOTE_ADDR")

    AuditLog.objects.create(
        event_type="LOGOUT",
        username=user.username,
        ip_address=ip,
        severity="LOW"
    )

    audit_logger.info("User logout", extra={
        'event_type': 'LOGOUT',
        'username': user.username,
        'ip_address': ip
    })


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):
    username = credentials.get("username", "UNKNOWN")
    ip = request.META.get("REMOTE_ADDR") if request else "unknown"

    AuditLog.objects.create(
        event_type="LOGIN_FAILED",
        username=username,
        ip_address=ip,
        severity="HIGH"
    )

    audit_logger.warning("Failed login attempt", extra={
        'event_type': 'LOGIN_FAILED',
        'username': username,
        'ip_address': ip
    })

    send_alert(
        subject="SIEM Alert: Failed Login Attempt",
        message=f"Failed login attempt detected.\nUsername: {username}\nIP: {ip}\nTimestamp: {AuditLog.objects.filter(event_type='LOGIN_FAILED').last().timestamp if AuditLog.objects.filter(event_type='LOGIN_FAILED').exists() else 'N/A'}"
    )


# 4️⃣ Transaction Sync (NEW)
from django.db.models.signals import post_save
from .models import Transaction

@receiver(post_save, sender=Transaction)
def log_transaction_to_es(sender, instance, created, **kwargs):
    if created:
        audit_logger.info(f"Transaction {instance.transaction_type}", extra={
            'event_type': 'TRANSACTION',
            'transaction_data': {
                'account_number': instance.account_number,
                'amount': float(instance.amount),
                'transaction_type': instance.transaction_type,
                'location': instance.location,
                'is_flagged': instance.is_flagged,
                'flag_reason': instance.flag_reason
            }
        })
