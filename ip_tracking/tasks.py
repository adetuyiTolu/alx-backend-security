from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import SuspiciousIP, RequestLog

SENSITIVE_PATHS = ['/admin', '/login']
REQUEST_THRESHOLD = 100  # requests per hour

@shared_task
def detect_suspicious_ips():
    """
    Task to flag suspicious IPs:
    - Exceeding 100 requests in the last hour
    - Accessing sensitive paths
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)

    # 1️⃣ Find IPs exceeding request threshold
    request_counts = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(count=models.Count('id'))
    )

    for entry in request_counts:
        if entry['count'] > REQUEST_THRESHOLD:
            SuspiciousIP.objects.get_or_create(
                ip_address=entry['ip_address'],
                reason=f"Exceeded {REQUEST_THRESHOLD} requests/hour"
            )

    # 2️⃣ Find IPs accessing sensitive paths
    sensitive_requests = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago,
        path__in=SENSITIVE_PATHS
    )

    for req in sensitive_requests:
        SuspiciousIP.objects.get_or_create(
            ip_address=req.ip_address,
            reason=f"Accessed sensitive path: {req.path}"
        )
