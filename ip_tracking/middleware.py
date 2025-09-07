from .models import RequestLog

class IPTrackingMiddleware:
    """
    Middleware to log IP address, timestamp, and path of every request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get client IP
        ip_address = self.get_client_ip(request)
        path = request.path

        # Log to database
        RequestLog.objects.create(ip_address=ip_address, path=path)

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """
        Retrieve the real client IP address, accounting for proxies.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # If there are multiple IPs, take the first one
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
