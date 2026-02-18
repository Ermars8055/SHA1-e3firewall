"""
Firewall Middleware: Automatic request filtering using Collatz Firewall
Intercepts incoming requests and verifies IPs against whitelist.
"""

import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

from firewall_gateway.core.firewall_engine import FirewallEngine
from firewall_gateway.models.firewall_models import IPWhitelist, AccessLog

logger = logging.getLogger(__name__)


class CollatzFirewallMiddleware(MiddlewareMixin):
    """
    Django middleware for Collatz Firewall protection.

    Checks all incoming requests against the whitelist before processing.
    Can be configured to:
    - Allow/block based on firewall status
    - Log all access attempts
    - Skip certain paths (e.g., health checks)
    """

    def __init__(self, get_response):
        """Initialize middleware with firewall engine."""
        super().__init__(get_response)
        self.get_response = get_response
        self.firewall_engine = FirewallEngine()

        # Configuration from Django settings
        self.enabled = getattr(settings, 'COLLATZ_FIREWALL_ENABLED', True)
        self.enforce = getattr(settings, 'COLLATZ_FIREWALL_ENFORCE', False)
        self.skip_paths = getattr(settings, 'COLLATZ_FIREWALL_SKIP_PATHS', [
            '/health/',
            '/status/',
            '/firewall/register/',
            '/firewall/verify/',
        ])
        self.log_all = getattr(settings, 'COLLATZ_FIREWALL_LOG_ALL', True)

    def get_client_ip(self, request) -> str:
        """
        Extract client IP from request.

        Handles proxies and X-Forwarded-For headers.
        """
        # Check X-Forwarded-For header (for proxies)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
            return ip

        # Fall back to REMOTE_ADDR
        return request.META.get('REMOTE_ADDR', '')

    def should_skip_path(self, path: str) -> bool:
        """Check if this path should skip firewall verification."""
        for skip_path in self.skip_paths:
            if path.startswith(skip_path):
                return True
        return False

    def process_request(self, request):
        """
        Process incoming request.

        Returns:
        - None: Request passes firewall, continue processing
        - JsonResponse: Request blocked, return error response
        """
        if not self.enabled:
            return None

        # Get client IP
        client_ip = self.get_client_ip(request)

        if not client_ip or client_ip == '':
            logger.warning("Could not extract client IP from request")
            if self.enforce:
                return JsonResponse(
                    {'error': 'Could not determine client IP'},
                    status=400
                )
            return None

        # Check if path should skip firewall
        if self.should_skip_path(request.path):
            return None

        # Try to find IP in whitelist
        try:
            whitelist_entry = IPWhitelist.objects.get(
                ip_address=client_ip,
                is_active=True
            )
        except IPWhitelist.DoesNotExist:
            # IP not whitelisted
            if self.log_all:
                AccessLog.objects.create(
                    ip_address=client_ip,
                    status=AccessLog.STATUS_BLOCKED,
                    request_path=request.path,
                    request_method=request.method,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    error_message='IP not in whitelist'
                )

            logger.warning(f"Request from non-whitelisted IP: {client_ip}")

            if self.enforce:
                return JsonResponse(
                    {'error': 'IP not whitelisted'},
                    status=403
                )
            return None

        # Verify IP using Collatz firewall
        verify_result = self.firewall_engine.verify_ip(
            client_ip,
            whitelist_entry.collatz_hash
        )

        if verify_result.is_allowed():
            # Update access info
            whitelist_entry.update_access_timestamp()

            # Log allowed access (optional)
            if self.log_all:
                AccessLog.objects.create(
                    ip_address=client_ip,
                    computed_hash=verify_result.hash_value,
                    status=AccessLog.STATUS_ALLOWED,
                    matched_whitelist=whitelist_entry,
                    request_path=request.path,
                    request_method=request.method,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    response_time_ms=int(verify_result.response_time_ms)
                )

            logger.debug(f"Access allowed for {client_ip}")
            return None

        else:
            # Hash mismatch - possible spoofing
            AccessLog.objects.create(
                ip_address=client_ip,
                computed_hash=verify_result.hash_value,
                status=AccessLog.STATUS_BLOCKED,
                request_path=request.path,
                request_method=request.method,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                error_message='Hash verification failed - possible IP spoofing',
                response_time_ms=int(verify_result.response_time_ms)
            )

            logger.error(f"Hash mismatch for {client_ip} - possible spoofing attack")

            if self.enforce:
                return JsonResponse(
                    {'error': 'Firewall verification failed'},
                    status=403
                )
            return None

    def process_response(self, request, response):
        """Add firewall headers to response."""
        if self.enabled:
            response['X-Firewall-Protected'] = 'Collatz'
            response['X-Content-Type-Options'] = 'nosniff'

        return response
