"""
Advanced Security API Endpoints
Endpoints for SHA1-E3 enhanced features: MFA, Rate Limiting, Anomaly Detection, Audit Logging
"""

import json
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt


# Get the analytics engine instance
def get_analytics_engine():
    """Get singleton analytics engine instance."""
    from django.apps import apps
    app_config = apps.get_app_config('firewall_gateway')
    if not hasattr(app_config, '_analytics_engine'):
        from .analytics_engine import AnalyticsEngine
        app_config._analytics_engine = AnalyticsEngine()
    return app_config._analytics_engine


# ============ MFA ENDPOINTS ============

@csrf_exempt
@require_http_methods(["POST"])
def create_mfa_challenge_api(request) -> JsonResponse:
    """
    Create SHA1-E3 based MFA challenge.
    Endpoint: POST /analytics/api/security/mfa/challenge/

    Expected JSON:
    {
        "device_ip": "192.168.1.1"
    }
    """
    try:
        data = json.loads(request.body)
        device_ip = data.get('device_ip', request.META.get('REMOTE_ADDR'))

        challenge = get_analytics_engine().advanced_security.create_sha1e3_mfa_challenge(
            "mfa_request", device_ip
        )

        return JsonResponse({
            'success': True,
            'challenge': challenge,
            'message': 'MFA challenge created successfully'
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def verify_mfa_challenge_api(request) -> JsonResponse:
    """
    Verify SHA1-E3 MFA challenge response.
    Endpoint: POST /analytics/api/security/mfa/verify/

    Expected JSON:
    {
        "challenge_id": "...",
        "provided_hash": "..."
    }
    """
    try:
        data = json.loads(request.body)
        challenge_id = data.get('challenge_id')
        provided_hash = data.get('provided_hash')

        if not challenge_id or not provided_hash:
            return JsonResponse({
                'success': False,
                'error': 'challenge_id and provided_hash required'
            }, status=400)

        result = get_analytics_engine().advanced_security.verify_sha1e3_mfa(
            challenge_id, provided_hash
        )

        status_code = 200 if result['success'] else 401
        return JsonResponse(result, status=status_code)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ============ RATE LIMITING ENDPOINTS ============

@csrf_exempt
@require_http_methods(["GET", "POST"])
def check_rate_limit_api(request) -> JsonResponse:
    """
    Check rate limit quota for device.
    Endpoint: GET/POST /analytics/api/security/rate-limit/

    Optional JSON:
    {
        "device_ip": "192.168.1.1",
        "time_window_minutes": 5
    }
    """
    try:
        if request.method == 'POST':
            data = json.loads(request.body)
            device_ip = data.get('device_ip', request.META.get('REMOTE_ADDR'))
            time_window = data.get('time_window_minutes', 5)
        else:
            device_ip = request.GET.get('device_ip', request.META.get('REMOTE_ADDR'))
            time_window = int(request.GET.get('time_window_minutes', 5))

        quota = get_analytics_engine().advanced_security.calculate_rate_limit_quota(
            device_ip, time_window
        )

        return JsonResponse(quota)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ============ ANOMALY DETECTION ENDPOINTS ============

@csrf_exempt
@require_http_methods(["POST"])
def detect_anomalies_api(request) -> JsonResponse:
    """
    Detect anomalies in device behavior using SHA1-E3 patterns.
    Endpoint: POST /analytics/api/security/anomaly-detection/

    Expected JSON:
    {
        "device_ip": "192.168.1.1",
        "sequence": [1, 2, 3, ...],
        "hash": "sha1e3_hash",
        "sequence_length": 100,
        "max_value": 50000
    }
    """
    try:
        data = json.loads(request.body)
        device_ip = data.get('device_ip')

        if not device_ip:
            device_ip = request.META.get('REMOTE_ADDR')

        sequence_data = {
            'sequence': data.get('sequence', []),
            'hash': data.get('hash', ''),
            'sequence_length': data.get('sequence_length', 0),
            'max_value': data.get('max_value', 0)
        }

        anomaly_result = get_analytics_engine().advanced_security.detect_anomalies(
            device_ip, sequence_data
        )

        return JsonResponse({
            'success': True,
            'device_ip': device_ip,
            'analysis': anomaly_result,
            'timestamp': str(__import__('datetime').datetime.now())
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_device_security_profile_api(request) -> JsonResponse:
    """
    Get security profile for a device.
    Endpoint: GET /analytics/api/security/device-profile/?device_ip=192.168.1.1
    """
    try:
        device_ip = request.GET.get('device_ip', request.META.get('REMOTE_ADDR'))

        profile = get_analytics_engine().advanced_security.get_device_security_profile(device_ip)

        return JsonResponse({
            'success': True,
            'profile': profile,
            'timestamp': str(__import__('datetime').datetime.now())
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ============ AUDIT LOGGING ENDPOINTS ============

@csrf_exempt
@require_http_methods(["POST"])
def log_audit_entry_api(request) -> JsonResponse:
    """
    Create audit log entry with hash chaining.
    Endpoint: POST /analytics/api/security/audit/log/

    Requires admin authentication!

    Expected JSON:
    {
        "action": "device_approved",
        "admin_id": "admin_username",
        "details": {"ip_address": "192.168.1.1", "reason": "..."}
    }
    """
    try:
        # Check admin authentication
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not get_analytics_engine().verify_admin_session(admin_token):
            return JsonResponse({
                'success': False,
                'error': 'Unauthorized - admin authentication required'
            }, status=401)

        data = json.loads(request.body)
        action = data.get('action')
        admin_id = data.get('admin_id', 'unknown')
        details = data.get('details', {})

        if not action:
            return JsonResponse({'success': False, 'error': 'action required'}, status=400)

        user_ip = request.META.get('REMOTE_ADDR')
        entry_hash = get_analytics_engine().advanced_security.create_audit_log_entry(
            action, user_ip, admin_id, details
        )

        return JsonResponse({
            'success': True,
            'message': 'Audit entry logged successfully',
            'entry_hash': entry_hash,
            'timestamp': str(__import__('datetime').datetime.now())
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def verify_audit_integrity_api(request) -> JsonResponse:
    """
    Verify audit log integrity (check for tampering).
    Endpoint: GET /analytics/api/security/audit/verify/

    Requires admin authentication!
    """
    try:
        # Check admin authentication
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not get_analytics_engine().verify_admin_session(admin_token):
            return JsonResponse({
                'success': False,
                'error': 'Unauthorized - admin authentication required'
            }, status=401)

        result = get_analytics_engine().advanced_security.verify_audit_log_integrity()

        return JsonResponse({
            'success': True,
            'integrity_check': result,
            'timestamp': str(__import__('datetime').datetime.now())
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_audit_logs_api(request) -> JsonResponse:
    """
    Get audit logs for a specific IP.
    Endpoint: GET /analytics/api/security/audit/logs/?device_ip=192.168.1.1&limit=50

    Requires admin authentication!
    """
    try:
        # Check admin authentication
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not get_analytics_engine().verify_admin_session(admin_token):
            return JsonResponse({
                'success': False,
                'error': 'Unauthorized - admin authentication required'
            }, status=401)

        device_ip = request.GET.get('device_ip')
        limit = int(request.GET.get('limit', 50))

        if not device_ip:
            device_ip = request.META.get('REMOTE_ADDR')

        logs = get_analytics_engine().advanced_security.get_audit_logs_for_ip(device_ip, limit)

        return JsonResponse({
            'success': True,
            'device_ip': device_ip,
            'logs': logs,
            'count': len(logs),
            'timestamp': str(__import__('datetime').datetime.now())
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ============ GEO-BLOCKING ENDPOINTS ============

@csrf_exempt
@require_http_methods(["POST"])
def enable_geo_blocking_api(request) -> JsonResponse:
    """
    Enable geographic blocking for a device.
    Endpoint: POST /analytics/api/security/geo-blocking/enable/

    Requires admin authentication!

    Expected JSON:
    {
        "device_ip": "192.168.1.1",
        "allowed_regions": ["US", "EU", "ASIA"]
    }
    """
    try:
        # Check admin authentication
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not get_analytics_engine().verify_admin_session(admin_token):
            return JsonResponse({
                'success': False,
                'error': 'Unauthorized - admin authentication required'
            }, status=401)

        data = json.loads(request.body)
        device_ip = data.get('device_ip')
        allowed_regions = data.get('allowed_regions', [])

        if not device_ip or not allowed_regions:
            return JsonResponse({
                'success': False,
                'error': 'device_ip and allowed_regions required'
            }, status=400)

        result = get_analytics_engine().advanced_security.enable_geo_blocking(
            device_ip, allowed_regions
        )

        # Log the action
        get_analytics_engine().advanced_security.create_audit_log_entry(
            'geo_blocking_enabled',
            request.META.get('REMOTE_ADDR'),
            data.get('admin_id', 'unknown'),
            {'device_ip': device_ip, 'regions': allowed_regions}
        )

        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ============ SECURITY DASHBOARD ENDPOINTS ============

@csrf_exempt
@require_http_methods(["GET"])
def get_security_dashboard_api(request) -> JsonResponse:
    """
    Get comprehensive security dashboard data.
    Endpoint: GET /analytics/api/security/dashboard/

    Requires admin authentication!
    """
    try:
        # Check admin authentication
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not get_analytics_engine().verify_admin_session(admin_token):
            return JsonResponse({
                'success': False,
                'error': 'Unauthorized - admin authentication required'
            }, status=401)

        # Gather security metrics
        audit_integrity = get_analytics_engine().advanced_security.verify_audit_log_integrity()
        audit_entry_count = len(get_analytics_engine().advanced_security.audit_log)
        device_profiles_count = len(get_analytics_engine().advanced_security.device_profiles)

        # Get high-threat devices
        high_threat_devices = [
            ip for ip in get_analytics_engine().advanced_security.device_profiles.keys()
            if get_analytics_engine().advanced_security._calculate_threat_level(ip) == 'high'
        ]

        # Get rate-limited IPs
        rate_limited = [
            ip for ip, tracker in get_analytics_engine().advanced_security.rate_limit_tracker.items()
            if tracker.get('blocked_until')
        ]

        return JsonResponse({
            'success': True,
            'dashboard': {
                'audit_logs': {
                    'total_entries': audit_entry_count,
                    'integrity_ok': audit_integrity['integrity_ok'],
                    'corrupted_entries': len(audit_integrity.get('corrupted_entries', []))
                },
                'devices': {
                    'total_profiled': device_profiles_count,
                    'high_threat_count': len(high_threat_devices),
                    'high_threat_devices': high_threat_devices[:10]  # Show top 10
                },
                'rate_limiting': {
                    'currently_blocked': len(rate_limited),
                    'blocked_ips': rate_limited[:10]  # Show top 10
                },
                'mfa_challenges': {
                    'active_challenges': len(get_analytics_engine().advanced_security.mfa_challenges),
                    'pending_verification': sum(
                        1 for c in get_analytics_engine().advanced_security.mfa_challenges.values()
                        if not c.get('verified')
                    )
                },
                'security_status': 'healthy' if audit_integrity['integrity_ok'] else 'compromised'
            },
            'timestamp': str(__import__('datetime').datetime.now())
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ============ SHA1-E3 ADMIN SESSION ENDPOINTS ============

@csrf_exempt
@require_http_methods(["GET"])
def verify_admin_session_chain_api(request) -> JsonResponse:
    """
    Verify SHA1-E3 admin session hash chain for tampering.
    Blockchain-style verification of all admin sessions.

    Endpoint: GET /analytics/api/security/admin/session/verify/

    Requires: admin_token cookie

    Response:
    {
        "success": true,
        "chain_integrity_ok": true,
        "total_sessions": 2,
        "verified_sessions": 2,
        "tampered_sessions": [],
        "verification_timestamp": "2026-02-02T..."
    }
    """
    admin_token = request.COOKIES.get('admin_token')
    if not admin_token or not get_analytics_engine().verify_admin_session(admin_token):
        return JsonResponse({
            'success': False,
            'error': 'Unauthorized - admin authentication required'
        }, status=401)

    try:
        analytics_engine = get_analytics_engine()
        chain_verification = analytics_engine.verify_admin_session_chain()

        return JsonResponse({
            'success': True,
            'data': chain_verification
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_admin_session_info_api(request) -> JsonResponse:
    """
    Get current admin session information with SHA1-E3 hashing details.

    Endpoint: GET /analytics/api/security/admin/session/info/

    Requires: admin_token cookie

    Response:
    {
        "success": true,
        "session": {
            "username": "admin",
            "login_time": "2026-02-02T...",
            "expires": "2026-02-02T...",
            "authentication_method": "SHA1-E3",
            "token_hash": "abcd1234...",
            "chain_integrity": true
        }
    }
    """
    admin_token = request.COOKIES.get('admin_token')
    if not admin_token:
        return JsonResponse({
            'success': False,
            'error': 'Unauthorized - no session token'
        }, status=401)

    try:
        analytics_engine = get_analytics_engine()

        # Verify session (includes tamper detection)
        is_valid = analytics_engine.verify_admin_session(admin_token)

        if not is_valid:
            return JsonResponse({
                'success': False,
                'error': 'Session invalid or tampered'
            }, status=401)

        session = analytics_engine.admin_sessions.get(admin_token, {})

        return JsonResponse({
            'success': True,
            'session': {
                'username': session.get('username'),
                'login_time': session.get('login_time'),
                'expires': session.get('expires'),
                'authentication_method': 'SHA1-E3',
                'token_hash': session.get('token_hash', 'N/A')[:32],
                'chain_integrity': not session.get('is_tampered', False),
                'tamper_status': 'CLEAN' if not session.get('is_tampered') else 'COMPROMISED'
            }
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
