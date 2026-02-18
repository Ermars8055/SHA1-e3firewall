"""
Access control decorators for service page protection.
"""

from functools import wraps
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect


def get_client_ip(request):
    """
    Get client IP from request, checking multiple headers for proxy/network scenarios.
    """
    # Check X-Forwarded-For header first (for proxies/load balancers)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
        return ip

    # Check CF-Connecting-IP (Cloudflare)
    cf_connecting_ip = request.META.get('HTTP_CF_CONNECTING_IP')
    if cf_connecting_ip:
        return cf_connecting_ip

    # Check X-Real-IP (nginx proxy)
    x_real_ip = request.META.get('HTTP_X_REAL_IP')
    if x_real_ip:
        return x_real_ip

    # Fall back to REMOTE_ADDR (direct connection)
    return request.META.get('REMOTE_ADDR', '')


def whitelist_required(view_func):
    """
    Decorator to check if requesting IP is whitelisted.
    Redirects to registration page if not whitelisted.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Import here to avoid circular imports
        from .views import analytics_engine

        # Get client IP using improved method
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')

        # Register device
        analytics_engine.register_device(ip_address, user_agent)

        # Verify IP is whitelisted
        verification = analytics_engine.verify_ip(ip_address)

        if verification['verified']:
            # IP is whitelisted, allow access
            return view_func(request, *args, **kwargs)
        else:
            # IP not whitelisted, redirect to registration
            # Pass the IP and device info to the registration view
            request.ip_address = ip_address
            request.device_info = analytics_engine.device_registry.get(ip_address, {})
            return redirect('analytics:registration')

    return wrapper
