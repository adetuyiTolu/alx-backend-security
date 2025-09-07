from .models import RequestLog
from django.http import HttpResponseForbidden
from .models import BlockedIP

import requests
from django.conf import settings
from django.core.cache import cache

class IPTrackingMiddleware:
    """
    Middleware to log request details with geolocation.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)
        path = request.path

        # Check cache for geolocation
        geo_data = cache.get(ip_address)
        if geo_data is None:
            geo_data = self.get_geolocation(ip_address)
            # Cache for 24 hours (86400 seconds)
            cache.set(ip_address, geo_data, 86400)

        RequestLog.objects.create(
            ip_address=ip_address,
            path=path,
            country=geo_data.get('country_name'),
            city=geo_data.get('city')
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get_geolocation(self, ip):
        try:
            url = f"https://api.ipgeolocation.io/ipgeo?apiKey={settings.IPGEOLOCATION_API_KEY}&ip={ip}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country_name': data.get('country_name'),
                    'city': data.get('city')
                }
        except Exception:
            pass
        return {'country_name': None, 'city': None}

class IPBlockMiddleware:
    """
    Middleware to block requests from blacklisted IPs.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Check if IP is blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Access denied: Your IP is blocked.")

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
