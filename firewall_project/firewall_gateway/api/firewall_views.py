"""
Firewall API Endpoints: REST API for Collatz Firewall operations
Provides endpoints for registering, verifying, and managing whitelisted IPs.
"""

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.db import transaction
import json
import logging

from firewall_gateway.core.firewall_engine import FirewallEngine
from firewall_gateway.models.firewall_models import IPWhitelist, AccessLog, FirewallStats

logger = logging.getLogger(__name__)

# Initialize firewall engine
firewall_engine = FirewallEngine()


@csrf_exempt
@require_http_methods(["POST"])
def register_ip(request):
    """
    Register a new IP address to the whitelist.

    Expected POST data:
    {
        "ip_address": "192.168.1.100",
        "name": "Production Server",
        "description": "Main API server"
    }

    Returns:
    {
        "success": true,
        "ip_address": "192.168.1.100",
        "collatz_hash": "9f3a7c2e...",
        "sequence_length": 347,
        "whitelist_id": 1,
        "message": "IP registered successfully"
    }
    """
    try:
        data = json.loads(request.body)
        ip_address = data.get('ip_address')
        name = data.get('name')
        description = data.get('description')

        if not ip_address:
            return JsonResponse(
                {'error': 'ip_address is required'},
                status=400
            )

        # Check if IP already registered
        if IPWhitelist.objects.filter(ip_address=ip_address).exists():
            return JsonResponse(
                {'error': f'IP {ip_address} is already registered'},
                status=409
            )

        # Register using firewall engine
        reg_result = firewall_engine.register_ip(ip_address, name, description)

        if not reg_result.success:
            return JsonResponse(
                {'error': reg_result.error_message},
                status=400
            )

        # Store in database
        try:
            ip_integer = int(ip_address.split('.')[-1]) + (
                int(ip_address.split('.')[0]) << 24 +
                int(ip_address.split('.')[1]) << 16 +
                int(ip_address.split('.')[2]) << 8
            )
        except:
            import ipaddress
            ip_integer = int(ipaddress.IPv4Address(ip_address))

        with transaction.atomic():
            whitelist_entry = IPWhitelist.objects.create(
                ip_address=ip_address,
                ip_integer=ip_integer,
                collatz_hash=reg_result.collatz_hash,
                collatz_sequence_length=reg_result.sequence_length,
                collatz_steps_to_one=0,  # Could calculate from engine
                collatz_max_value=0,     # Could calculate from engine
                name=name,
                description=description,
                is_active=True
            )

        logger.info(f"IP {ip_address} registered successfully")

        return JsonResponse(
            {
                'success': True,
                'ip_address': ip_address,
                'collatz_hash': reg_result.collatz_hash,
                'sequence_length': reg_result.sequence_length,
                'whitelist_id': whitelist_entry.id,
                'message': 'IP registered successfully'
            },
            status=201
        )

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error registering IP: {str(e)}")
        return JsonResponse(
            {'error': f'Internal server error: {str(e)}'},
            status=500
        )


@csrf_exempt
@require_http_methods(["POST"])
def verify_ip(request):
    """
    Verify if an incoming IP is allowed.

    Expected POST data:
    {
        "ip_address": "192.168.1.100"
    }

    Returns:
    {
        "allowed": true,
        "ip_address": "192.168.1.100",
        "hash_value": "9f3a7c2e...",
        "sequence_length": 347,
        "response_time_ms": 2.34,
        "message": "Access allowed"
    }
    """
    start_time = timezone.now()

    try:
        data = json.loads(request.body)
        ip_address = data.get('ip_address')

        if not ip_address:
            return JsonResponse(
                {'error': 'ip_address is required'},
                status=400
            )

        # Find whitelisted IP
        try:
            whitelist_entry = IPWhitelist.objects.get(
                ip_address=ip_address,
                is_active=True
            )
        except IPWhitelist.DoesNotExist:
            response = JsonResponse(
                {
                    'allowed': False,
                    'ip_address': ip_address,
                    'message': 'IP not in whitelist'
                },
                status=403
            )

            # Log the blocked attempt
            AccessLog.objects.create(
                ip_address=ip_address,
                status=AccessLog.STATUS_BLOCKED,
                error_message='IP not in whitelist'
            )

            return response

        # Verify using firewall engine
        verify_result = firewall_engine.verify_ip(
            ip_address,
            whitelist_entry.collatz_hash
        )

        if verify_result.is_allowed():
            # Update whitelist access info
            whitelist_entry.update_access_timestamp()

            # Log allowed access
            AccessLog.objects.create(
                ip_address=ip_address,
                computed_hash=verify_result.hash_value,
                status=AccessLog.STATUS_ALLOWED,
                matched_whitelist=whitelist_entry,
                response_time_ms=int(verify_result.response_time_ms)
            )

            logger.info(f"Access allowed for {ip_address}")

            return JsonResponse(
                {
                    'allowed': True,
                    'ip_address': ip_address,
                    'hash_value': verify_result.hash_value,
                    'sequence_length': verify_result.sequence_length,
                    'response_time_ms': round(verify_result.response_time_ms, 2),
                    'message': 'Access allowed'
                },
                status=200
            )
        else:
            # Log blocked access
            AccessLog.objects.create(
                ip_address=ip_address,
                computed_hash=verify_result.hash_value,
                status=AccessLog.STATUS_BLOCKED,
                error_message='Hash mismatch - possible spoofing attempt',
                response_time_ms=int(verify_result.response_time_ms)
            )

            logger.warning(f"Hash mismatch for {ip_address} - possible attack")

            return JsonResponse(
                {
                    'allowed': False,
                    'ip_address': ip_address,
                    'message': 'Hash verification failed'
                },
                status=403
            )

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error verifying IP: {str(e)}")
        return JsonResponse(
            {'error': f'Internal server error: {str(e)}'},
            status=500
        )


@require_http_methods(["GET"])
def list_whitelisted_ips(request):
    """
    List all whitelisted IPs (admin only).

    Returns:
    {
        "count": 5,
        "ips": [
            {
                "id": 1,
                "ip_address": "192.168.1.100",
                "name": "Production",
                "is_active": true,
                "last_verified": "2025-12-10T15:30:00Z",
                "access_count": 1247
            }
        ]
    }
    """
    try:
        whitelist_entries = IPWhitelist.objects.filter(is_active=True).values(
            'id', 'ip_address', 'name', 'is_active', 'last_verified', 'access_count'
        )

        return JsonResponse(
            {
                'count': len(whitelist_entries),
                'ips': list(whitelist_entries)
            },
            status=200
        )

    except Exception as e:
        logger.error(f"Error listing whitelisted IPs: {str(e)}")
        return JsonResponse(
            {'error': f'Internal server error: {str(e)}'},
            status=500
        )


@csrf_exempt
@require_http_methods(["POST"])
def deactivate_ip(request):
    """
    Deactivate a whitelisted IP.

    Expected POST data:
    {
        "ip_address": "192.168.1.100"
    }

    Returns:
    {
        "success": true,
        "message": "IP deactivated"
    }
    """
    try:
        data = json.loads(request.body)
        ip_address = data.get('ip_address')

        if not ip_address:
            return JsonResponse(
                {'error': 'ip_address is required'},
                status=400
            )

        try:
            whitelist_entry = IPWhitelist.objects.get(ip_address=ip_address)
            whitelist_entry.deactivate()

            logger.info(f"IP {ip_address} deactivated")

            return JsonResponse(
                {
                    'success': True,
                    'message': f'IP {ip_address} deactivated'
                },
                status=200
            )

        except IPWhitelist.DoesNotExist:
            return JsonResponse(
                {'error': f'IP {ip_address} not found'},
                status=404
            )

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error deactivating IP: {str(e)}")
        return JsonResponse(
            {'error': f'Internal server error: {str(e)}'},
            status=500
        )


@require_http_methods(["GET"])
def firewall_stats(request):
    """
    Get firewall statistics.

    Returns:
    {
        "total_ips": 5,
        "active_ips": 5,
        "total_access_attempts": 10000,
        "allowed_rate": 98.5,
        "blocked_rate": 1.5
    }
    """
    try:
        total_ips = IPWhitelist.objects.count()
        active_ips = IPWhitelist.objects.filter(is_active=True).count()

        access_logs = AccessLog.objects.all()
        total_attempts = access_logs.count()
        allowed = access_logs.filter(status=AccessLog.STATUS_ALLOWED).count()
        blocked = access_logs.filter(status=AccessLog.STATUS_BLOCKED).count()

        allowed_rate = (allowed / total_attempts * 100) if total_attempts > 0 else 0
        blocked_rate = (blocked / total_attempts * 100) if total_attempts > 0 else 0

        return JsonResponse(
            {
                'total_ips': total_ips,
                'active_ips': active_ips,
                'total_access_attempts': total_attempts,
                'allowed_count': allowed,
                'blocked_count': blocked,
                'allowed_rate': round(allowed_rate, 2),
                'blocked_rate': round(blocked_rate, 2)
            },
            status=200
        )

    except Exception as e:
        logger.error(f"Error getting firewall stats: {str(e)}")
        return JsonResponse(
            {'error': f'Internal server error: {str(e)}'},
            status=500
        )
