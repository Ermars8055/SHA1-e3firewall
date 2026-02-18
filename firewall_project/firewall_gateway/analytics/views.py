"""
Analytics Dashboard Views: Django views for analytics API and dashboard
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.views import View
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from typing import Dict, Any, List
import json
from datetime import timedelta

from .analytics_engine import AnalyticsEngine


# Global analytics engine instance
analytics_engine = AnalyticsEngine()


def dashboard_view(request):
    """
    Render the analytics dashboard.
    """
    from django.http import HttpResponse
    import os

    template_path = os.path.join(os.path.dirname(__file__), 'templates', 'analytics', 'index.html')
    with open(template_path, 'r') as f:
        return HttpResponse(f.read())


@require_http_methods(["GET"])
def get_stats_api(request) -> JsonResponse:
    """
    API endpoint: Get current statistics.

    Returns:
        JSON with current firewall statistics
    """
    stats = analytics_engine.get_performance_summary()
    return JsonResponse(stats)


@require_http_methods(["GET"])
def get_patterns_api(request) -> JsonResponse:
    """
    API endpoint: Get detected patterns.

    Returns:
        JSON with pattern analysis results
    """
    patterns = analytics_engine.get_pattern_summary()
    pattern_data = {}
    for pattern_type, stats in patterns.items():
        pattern_data[pattern_type] = {
            'count': stats.get('count', 0),
            'avg_confidence': round(stats.get('avg_confidence', 0), 3),
            'frequency': stats.get('frequency', 0)
        }
    return JsonResponse(pattern_data)


@require_http_methods(["GET"])
def get_innovations_api(request) -> JsonResponse:
    """
    API endpoint: Get innovation suggestions.

    Returns:
        JSON with innovation recommendations
    """
    suggestions = analytics_engine.get_innovation_suggestions()
    suggestion_data = []
    for sugg in suggestions:
        suggestion_data.append({
            'title': sugg.title,
            'description': sugg.description,
            'category': sugg.category,
            'impact': sugg.impact,
            'implementation_complexity': sugg.implementation_complexity,
            'estimated_benefit': sugg.estimated_benefit
        })
    return JsonResponse(suggestion_data, safe=False)


@require_http_methods(["POST"])
def analyze_sequence_api(request) -> JsonResponse:
    """
    API endpoint: Analyze a Collatz sequence.

    Expected JSON body:
    {
        'ip_address': '192.168.1.1',
        'sequence': [n1, n2, n3, ...],
        'sequence_length': 340,
        'max_value': 1000000,
        'steps_to_one': 339
    }

    Returns:
        JSON with sequence analysis
    """
    try:
        import json
        data = json.loads(request.body)

        ip_address = data.get('ip_address')
        sequence = data.get('sequence', [])
        sequence_length = data.get('sequence_length', 0)
        max_value = data.get('max_value', 0)
        steps_to_one = data.get('steps_to_one', 0)

        if not ip_address or not sequence:
            return JsonResponse({
                'success': False,
                'error': 'Missing required fields: ip_address, sequence'
            }, status=400)

        # Analyze the sequence
        analysis = analytics_engine.analyze_sequence(
            ip_address=ip_address,
            sequence=sequence,
            sequence_length=sequence_length,
            max_value=max_value,
            steps_to_one=steps_to_one
        )

        return JsonResponse({
            'success': True,
            'analysis': {
                'ip': analysis['ip'],
                'is_suspicious': analysis['is_suspicious'],
                'risk_score': round(analysis['risk_score'], 3),
                'anomalies': analysis['anomalies'],
                'patterns': [
                    {
                        'type': p.pattern_type,
                        'frequency': p.frequency,
                        'confidence': round(p.confidence, 3),
                        'max_value': p.max_value,
                        'min_value': p.min_value
                    }
                    for p in analysis['patterns']
                ],
                'metrics': {
                    k: round(v, 3) if isinstance(v, float) else v
                    for k, v in analysis['metrics'].items()
                }
            },
            'timestamp': str(__import__('datetime').datetime.now())
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request body'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def record_verification_api(request) -> JsonResponse:
    """
    API endpoint: Record a verification event for metrics.

    Expected JSON body:
    {
        'verification_time_ms': 2.5,
        'was_allowed': true,
        'ip_address': '192.168.1.1'  // optional
    }

    Returns:
        JSON with updated metrics
    """
    try:
        import json
        data = json.loads(request.body)

        verification_time = data.get('verification_time_ms', 0)
        was_allowed = data.get('was_allowed', False)
        ip_address = data.get('ip_address', 'unknown')

        analytics_engine.update_performance_metrics(
            verification_time_ms=verification_time,
            was_allowed=was_allowed,
            ip_address=ip_address
        )

        # Generate synthetic Collatz sequence for pattern detection
        import random
        start_num = random.randint(10, 10000)
        sequence = []
        num = start_num
        while num != 1 and len(sequence) < 500:
            sequence.append(num)
            if num % 2 == 0:
                num = num // 2
            else:
                num = 3 * num + 1

        if sequence:
            analytics_engine.analyze_sequence(
                ip_address=ip_address,
                sequence=sequence,
                sequence_length=len(sequence),
                max_value=max(sequence) if sequence else 0,
                steps_to_one=len(sequence)
            )

        stats = analytics_engine.get_performance_summary()

        return JsonResponse({
            'success': True,
            'message': 'Verification recorded',
            'updated_stats': stats,
            'timestamp': str(__import__('datetime').datetime.now())
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request body'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def get_dashboard_summary_api(request) -> JsonResponse:
    """
    API endpoint: Get complete dashboard summary (all data at once).

    Returns:
        JSON with all dashboard information
    """
    try:
        stats = analytics_engine.get_performance_summary()
        patterns = analytics_engine.get_pattern_summary()
        suggestions = analytics_engine.get_innovation_suggestions()

        # Format data
        pattern_data = {}
        for pattern_type, pstats in patterns.items():
            pattern_data[pattern_type] = {
                'count': pstats.get('count', 0),
                'avg_confidence': round(pstats.get('avg_confidence', 0), 3),
                'frequency': pstats.get('frequency', 0)
            }

        suggestion_data = []
        for sugg in suggestions:
            suggestion_data.append({
                'title': sugg.title,
                'description': sugg.description,
                'category': sugg.category,
                'impact': sugg.impact,
                'implementation_complexity': sugg.implementation_complexity,
                'estimated_benefit': sugg.estimated_benefit
            })

        return JsonResponse({
            'success': True,
            'dashboard': {
                'stats': stats,
                'patterns': pattern_data,
                'suggestions': suggestion_data,
                'analytics_enabled': True,
                'update_interval_ms': 2000
            },
            'timestamp': str(__import__('datetime').datetime.now())
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


class AnalyticsDashboardView(View):
    """
    Class-based view for analytics dashboard.
    """

    def get(self, request):
        """Render dashboard page."""
        return dashboard_view(request)


class AnalyticsAPIView(View):
    """
    Class-based view for analytics API operations.
    """

    def get(self, request):
        """Get summary data."""
        return get_dashboard_summary_api(request)

    def post(self, request):
        """Post analysis or metric recording."""
        action = request.GET.get('action', 'record')

        if action == 'analyze':
            return analyze_sequence_api(request)
        elif action == 'record':
            return record_verification_api(request)
        else:
            return JsonResponse({
                'success': False,
                'error': f'Unknown action: {action}'
            }, status=400)


@require_http_methods(["GET"])
def get_verifications_api(request) -> JsonResponse:
    """
    API endpoint: Get recent verifications.
    """
    verifications = analytics_engine.verification_log[-20:] if hasattr(analytics_engine, 'verification_log') else []
    return JsonResponse(verifications, safe=False)


# Whitelist verification endpoint
@csrf_exempt
@require_http_methods(["GET", "POST"])
def verify_ip_api(request) -> JsonResponse:
    """
    API endpoint: Verify IP against whitelist.
    GET: Extract client IP from request
    POST: Verify specific IP
    """
    try:
        if request.method == 'POST':
            import json
            data = json.loads(request.body)
            ip_address = data.get('ip_address')
        else:
            ip_address = request.META.get('REMOTE_ADDR')

        # Get user agent and register device
        user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
        analytics_engine.register_device(ip_address, user_agent)

        result = analytics_engine.verify_ip(ip_address)

        # Log the verification to activity log
        is_allowed = result.get('verified', False)
        analytics_engine.update_performance_metrics(
            verification_time_ms=0.5,
            was_allowed=is_allowed,
            ip_address=ip_address
        )

        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# Whitelist management endpoints
@csrf_exempt
@require_http_methods(["POST"])
def whitelist_ip_api(request) -> JsonResponse:
    """
    API endpoint: Add IP to whitelist.
    REQUIRES ADMIN AUTHENTICATION
    """
    try:
        # Check admin authentication
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not analytics_engine.verify_admin_session(admin_token):
            return JsonResponse({'success': False, 'error': 'Unauthorized - admin authentication required'}, status=401)

        import json
        data = json.loads(request.body)
        ip_address = data.get('ip_address')

        if not ip_address:
            return JsonResponse({'error': 'ip_address required'}, status=400)

        result = analytics_engine.whitelist_ip(ip_address)
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST", "DELETE"])
def remove_whitelist_api(request) -> JsonResponse:
    """
    API endpoint: Remove IP from whitelist.
    REQUIRES ADMIN AUTHENTICATION
    """
    try:
        # Check admin authentication
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not analytics_engine.verify_admin_session(admin_token):
            return JsonResponse({'success': False, 'error': 'Unauthorized - admin authentication required'}, status=401)

        if request.method == 'DELETE':
            import json
            data = json.loads(request.body)
            ip_address = data.get('ip_address')
        else:
            import json
            data = json.loads(request.body)
            ip_address = data.get('ip_address')

        if not ip_address:
            return JsonResponse({'error': 'ip_address required'}, status=400)

        result = analytics_engine.remove_from_whitelist(ip_address)
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["GET"])
def get_whitelist_api(request) -> JsonResponse:
    """
    API endpoint: Get current whitelist.
    """
    whitelist = analytics_engine.get_whitelist()
    return JsonResponse(whitelist)


@require_http_methods(["GET"])
def get_devices_api(request) -> JsonResponse:
    """
    API endpoint: Get all connected devices with their info.
    """
    devices = analytics_engine.device_registry
    return JsonResponse(devices)


# Network info endpoint
@require_http_methods(["GET"])
def get_network_info_api(request) -> JsonResponse:
    """
    API endpoint: Get network information.

    Returns:
        JSON with network and system info
    """
    network_info = analytics_engine.get_network_info()
    return JsonResponse(network_info)


# Health check endpoint
@require_http_methods(["GET"])
def analytics_health_api(request) -> JsonResponse:
    """
    API endpoint: Health check for analytics service.

    Returns:
        JSON with service health status
    """
    return JsonResponse({
        'success': True,
        'service': 'analytics',
        'status': 'healthy',
        'version': '1.0.0',
        'timestamp': str(__import__('datetime').datetime.now())
    })


# Service page endpoints
from .decorators import whitelist_required, get_client_ip
from django.contrib.auth.decorators import login_required
import hashlib


@whitelist_required
def service_page_view(request):
    """
    Protected service page - only whitelisted IPs can access.
    """
    from django.http import HttpResponse
    import os

    ip_address = get_client_ip(request)
    device_info = analytics_engine.device_registry.get(ip_address, {})

    # Create HTML response for protected service
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Firewall Gateway - Protected Service</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                background: linear-gradient(135deg, #0a0e27 0%, #151d3b 100%);
                color: #e0e0e0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .container {{
                background: rgba(15, 20, 40, 0.95);
                border: 1px solid rgba(100, 150, 255, 0.3);
                border-radius: 10px;
                padding: 40px;
                max-width: 800px;
                width: 100%;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
            }}
            .header {{
                display: flex;
                align-items: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid rgba(100, 150, 255, 0.3);
            }}
            .status-badge {{
                background: linear-gradient(135deg, #00d084 0%, #00b876 100%);
                color: white;
                padding: 8px 16px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: bold;
                margin-right: auto;
            }}
            h1 {{
                color: #6496ff;
                font-size: 28px;
                margin-bottom: 10px;
            }}
            .device-info {{
                background: rgba(100, 150, 255, 0.1);
                border: 1px solid rgba(100, 150, 255, 0.2);
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 30px;
            }}
            .info-row {{
                display: flex;
                justify-content: space-between;
                padding: 12px 0;
                border-bottom: 1px solid rgba(100, 150, 255, 0.1);
            }}
            .info-row:last-child {{
                border-bottom: none;
            }}
            .label {{
                color: #6496ff;
                font-weight: 600;
            }}
            .value {{
                color: #e0e0e0;
                word-break: break-all;
            }}
            .service-content {{
                background: rgba(100, 150, 255, 0.05);
                padding: 30px;
                border-radius: 8px;
                border: 1px solid rgba(100, 150, 255, 0.15);
            }}
            .service-title {{
                color: #6496ff;
                font-size: 20px;
                margin-bottom: 20px;
                font-weight: bold;
            }}
            .service-feature {{
                margin: 15px 0;
                padding: 12px;
                background: rgba(100, 150, 255, 0.1);
                border-left: 3px solid #6496ff;
                border-radius: 4px;
            }}
            .action-buttons {{
                display: flex;
                gap: 10px;
                margin-top: 30px;
            }}
            .btn {{
                flex: 1;
                padding: 12px 24px;
                border: none;
                border-radius: 6px;
                font-size: 14px;
                font-weight: bold;
                cursor: pointer;
                transition: all 0.3s ease;
            }}
            .btn-primary {{
                background: linear-gradient(135deg, #6496ff 0%, #4a7fff 100%);
                color: white;
            }}
            .btn-primary:hover {{
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(100, 150, 255, 0.4);
            }}
            .btn-secondary {{
                background: rgba(100, 150, 255, 0.2);
                color: #6496ff;
                border: 1px solid #6496ff;
            }}
            .btn-secondary:hover {{
                background: rgba(100, 150, 255, 0.3);
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <h1>🔒 Protected Service</h1>
                    <p style="color: #999; margin-top: 5px;">You have authorized access</p>
                </div>
                <div class="status-badge">✓ VERIFIED</div>
            </div>

            <div class="device-info">
                <div class="info-row">
                    <span class="label">Device Type:</span>
                    <span class="value">{device_info.get('device_type', 'Unknown')}</span>
                </div>
                <div class="info-row">
                    <span class="label">IP Address:</span>
                    <span class="value">{ip_address}</span>
                </div>
                <div class="info-row">
                    <span class="label">Status:</span>
                    <span class="value" style="color: #00d084;">✓ Whitelisted & Authorized</span>
                </div>
            </div>

            <div class="service-content">
                <div class="service-title">Available Services</div>
                <div class="service-feature">
                    <strong>Network Access Control</strong> - Manage and monitor your network devices with Collatz-based sequence verification
                </div>
                <div class="service-feature">
                    <strong>Real-time Analytics</strong> - View live traffic patterns and security metrics from your firewall gateway
                </div>
                <div class="service-feature">
                    <strong>Device Management</strong> - Approve, reject, and monitor connected devices on your network
                </div>
                <div class="service-feature">
                    <strong>Security Insights</strong> - Get AI-powered recommendations to strengthen your network security
                </div>
            </div>

            <div class="action-buttons">
                <button class="btn btn-primary" onclick="window.location.href='/analytics/'">
                    📊 Go to Dashboard
                </button>
                <button class="btn btn-secondary" onclick="window.location.href='/analytics/api/health/'">
                    🔍 Check Status
                </button>
            </div>
        </div>
    </body>
    </html>
    """
    return HttpResponse(html)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def registration_page_view(request):
    """
    Registration page - Shows pending devices and allows admin approval.
    """
    from django.http import HttpResponse
    import json

    if request.method == 'POST':
        # Handle admin approval/rejection
        try:
            data = json.loads(request.body)
            ip_address = data.get('ip_address')
            action = data.get('action')  # 'approve' or 'reject'

            if action == 'approve':
                result = analytics_engine.approve_device(ip_address)
                return JsonResponse({
                    'success': result['success'],
                    'message': result['message']
                })
            elif action == 'reject':
                result = analytics_engine.reject_device(ip_address)
                return JsonResponse({
                    'success': result['success'],
                    'message': result['message']
                })
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)

    # GET - Show pending devices and registration form
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')

    # Register the device if not already registered
    analytics_engine.register_device(ip_address, user_agent)

    device_info = analytics_engine.device_registry.get(ip_address, {})
    pending_devices = analytics_engine.get_pending_devices()
    whitelist = analytics_engine.get_whitelist()

    # Check if this IP is already registered (pending or approved)
    is_pending = ip_address in pending_devices
    is_whitelisted = ip_address in whitelist['whitelisted_ips']

    pending_html = ""
    if pending_devices:
        pending_html = "<div class='pending-devices'><h3>Pending Device Approvals</h3>"
        for ip, info in pending_devices.items():
            # Only show approve/reject buttons if viewing from DIFFERENT IP (admin approval)
            is_admin_viewing = ip != ip_address
            action_buttons = ""
            if is_admin_viewing:
                action_buttons = f"""
                    <button class="btn-approve" onclick="approveDevice('{ip}')">✓ Approve</button>
                    <button class="btn-reject" onclick="rejectDevice('{ip}')">✗ Reject</button>
                """
            else:
                action_buttons = """
                    <span style="color: #999; font-size: 12px;">⏳ Waiting for network admin approval...</span>
                """

            pending_html += f"""
            <div class="pending-item">
                <div class="device-row">
                    <strong>{info.get('device_type', 'Unknown')} - {ip}</strong>
                    <span class="status-pending">PENDING</span>
                </div>
                <div class="device-details">
                    <small>Requested: {info.get('timestamp', 'N/A')}</small>
                </div>
                <div class="device-actions">
                    {action_buttons}
                </div>
            </div>
            """
        pending_html += "</div>"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Device Registration - Firewall Gateway</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                background: linear-gradient(135deg, #0a0e27 0%, #151d3b 100%);
                color: #e0e0e0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{
                max-width: 900px;
                margin: 0 auto;
            }}
            .header {{
                text-align: center;
                margin-bottom: 40px;
            }}
            .header h1 {{
                color: #6496ff;
                font-size: 32px;
                margin-bottom: 10px;
            }}
            .header p {{
                color: #999;
                font-size: 14px;
            }}
            .section {{
                background: rgba(15, 20, 40, 0.95);
                border: 1px solid rgba(100, 150, 255, 0.3);
                border-radius: 10px;
                padding: 30px;
                margin-bottom: 30px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
            }}
            .section-title {{
                color: #6496ff;
                font-size: 18px;
                font-weight: bold;
                margin-bottom: 20px;
                display: flex;
                align-items: center;
            }}
            .section-title::before {{
                content: '';
                display: inline-block;
                width: 4px;
                height: 20px;
                background: #6496ff;
                margin-right: 10px;
                border-radius: 2px;
            }}
            .device-status {{
                background: rgba(100, 150, 255, 0.1);
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #6496ff;
            }}
            .device-info-row {{
                display: flex;
                justify-content: space-between;
                padding: 10px 0;
                border-bottom: 1px solid rgba(100, 150, 255, 0.1);
            }}
            .device-info-row:last-child {{
                border-bottom: none;
            }}
            .label {{
                color: #6496ff;
                font-weight: 600;
            }}
            .value {{
                color: #e0e0e0;
                word-break: break-all;
            }}
            .status-badge {{
                display: inline-block;
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: bold;
            }}
            .status-pending {{
                background: rgba(255, 165, 0, 0.3);
                color: #ffa500;
            }}
            .status-whitelisted {{
                background: rgba(0, 208, 132, 0.3);
                color: #00d084;
            }}
            .pending-devices {{
                margin-top: 20px;
            }}
            .pending-item {{
                background: rgba(100, 150, 255, 0.05);
                border: 1px solid rgba(100, 150, 255, 0.2);
                padding: 15px;
                margin-bottom: 15px;
                border-radius: 6px;
            }}
            .device-row {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 10px;
            }}
            .device-row strong {{
                color: #e0e0e0;
            }}
            .device-details {{
                color: #999;
                font-size: 12px;
                margin-bottom: 10px;
            }}
            .device-actions {{
                display: flex;
                gap: 10px;
            }}
            .btn-approve, .btn-reject {{
                flex: 1;
                padding: 10px 20px;
                border: none;
                border-radius: 4px;
                font-size: 12px;
                font-weight: bold;
                cursor: pointer;
                transition: all 0.3s ease;
            }}
            .btn-approve {{
                background: rgba(0, 208, 132, 0.3);
                color: #00d084;
                border: 1px solid #00d084;
            }}
            .btn-approve:hover {{
                background: rgba(0, 208, 132, 0.5);
            }}
            .btn-reject {{
                background: rgba(255, 75, 75, 0.3);
                color: #ff4b4b;
                border: 1px solid #ff4b4b;
            }}
            .btn-reject:hover {{
                background: rgba(255, 75, 75, 0.5);
            }}
            .message {{
                padding: 15px;
                border-radius: 6px;
                margin-bottom: 20px;
                display: none;
            }}
            .message.success {{
                background: rgba(0, 208, 132, 0.2);
                border: 1px solid #00d084;
                color: #00d084;
            }}
            .message.error {{
                background: rgba(255, 75, 75, 0.2);
                border: 1px solid #ff4b4b;
                color: #ff4b4b;
            }}
            .info-box {{
                background: rgba(100, 150, 255, 0.1);
                border: 1px solid rgba(100, 150, 255, 0.2);
                padding: 15px;
                border-radius: 6px;
                margin-bottom: 20px;
            }}
            .info-box p {{
                line-height: 1.6;
                color: #ccc;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 Device Registration</h1>
                <p>Request access to the Firewall Gateway service</p>
            </div>

            <div id="message" class="message"></div>

            <div class="section">
                <div class="section-title">Your Device Status</div>
                <div class="device-status">
                    <div class="device-info-row">
                        <span class="label">Device Type:</span>
                        <span class="value">{device_info.get('device_type', 'Unknown')}</span>
                    </div>
                    <div class="device-info-row">
                        <span class="label">IP Address:</span>
                        <span class="value">{ip_address}</span>
                    </div>
                    <div class="device-info-row">
                        <span class="label">Status:</span>
                        <span class="value">
                            {'<span class="status-badge status-pending">⏳ Pending Approval</span>' if is_pending else ''}
                            {'<span class="status-badge status-whitelisted">✓ Whitelisted</span>' if is_whitelisted else ''}
                            {'' if not is_pending and not is_whitelisted else ''}
                        </span>
                    </div>
                </div>

                {'<div class="info-box"><p><strong>✓ Device Approved!</strong> Your device has been whitelisted and can now access the service. <a href="/analytics/service/" style="color: #6496ff;">Click here to access</a></p></div>' if is_whitelisted else ''}
                {'<div class="info-box"><p><strong>⏳ Pending Approval</strong> Your device is waiting for administrator approval. Once approved, you will be able to access the service.</p></div>' if is_pending else ''}
                {'' if is_pending or is_whitelisted else '<div class="info-box"><p><strong>Request Submitted</strong> Your device has been registered. Wait for administrator approval to access the service.</p></div>'}
            </div>

            {pending_html}

            <div class="section" style="text-align: center; color: #999; font-size: 12px;">
                <p>📡 Connected Devices: {len(analytics_engine.device_registry)}</p>
                <p>✓ Whitelisted: {whitelist['count']}</p>
            </div>
        </div>

        <script>
            function approveDevice(ip) {{
                if (!confirm(`Approve device with IP: ${{ip}}?`)) return;

                fetch('/analytics/api/approve/', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{ip_address: ip, action: 'approve'}})
                }})
                .then(r => r.json())
                .then(data => {{
                    showMessage(data.message, data.success ? 'success' : 'error');
                    if (data.success) setTimeout(() => location.reload(), 1500);
                }})
                .catch(e => showMessage('Error: ' + e, 'error'));
            }}

            function rejectDevice(ip) {{
                if (!confirm(`Reject device with IP: ${{ip}}?`)) return;

                fetch('/analytics/api/reject/', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{ip_address: ip, action: 'reject'}})
                }})
                .then(r => r.json())
                .then(data => {{
                    showMessage(data.message, data.success ? 'success' : 'error');
                    if (data.success) setTimeout(() => location.reload(), 1500);
                }})
                .catch(e => showMessage('Error: ' + e, 'error'));
            }}

            function showMessage(text, type) {{
                const msg = document.getElementById('message');
                msg.textContent = text;
                msg.className = 'message ' + type;
                msg.style.display = 'block';
            }}
        </script>
    </body>
    </html>
    """
    return HttpResponse(html)


@csrf_exempt
@require_http_methods(["POST"])
def approve_device_api(request) -> JsonResponse:
    """
    API endpoint: Approve a pending device.
    REQUIRES ADMIN AUTHENTICATION
    """
    try:
        # Check admin authentication
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not analytics_engine.verify_admin_session(admin_token):
            return JsonResponse({'success': False, 'error': 'Unauthorized - admin authentication required'}, status=401)

        import json
        data = json.loads(request.body)
        ip_address = data.get('ip_address')

        if not ip_address:
            return JsonResponse({'success': False, 'error': 'ip_address required'}, status=400)

        result = analytics_engine.approve_device(ip_address)
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def reject_device_api(request) -> JsonResponse:
    """
    API endpoint: Reject a pending device.
    REQUIRES ADMIN AUTHENTICATION
    """
    try:
        # Check admin authentication
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not analytics_engine.verify_admin_session(admin_token):
            return JsonResponse({'success': False, 'error': 'Unauthorized - admin authentication required'}, status=401)

        import json
        data = json.loads(request.body)
        ip_address = data.get('ip_address')

        if not ip_address:
            return JsonResponse({'success': False, 'error': 'ip_address required'}, status=400)

        result = analytics_engine.reject_device(ip_address)
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@require_http_methods(["GET"])
def get_pending_devices_api(request) -> JsonResponse:
    """
    API endpoint: Get all pending device approvals.
    REQUIRES ADMIN AUTHENTICATION
    """
    # Check admin authentication
    admin_token = request.COOKIES.get('admin_token')
    if not admin_token or not analytics_engine.verify_admin_session(admin_token):
        return JsonResponse({'success': False, 'error': 'Unauthorized - admin authentication required'}, status=401)

    pending = analytics_engine.get_pending_devices()
    return JsonResponse(pending)


@require_http_methods(["GET"])
def patterns_page_view(request):
    """
    Patterns visualization page - Shows Collatz sequences as graphs.
    """
    from django.http import HttpResponse

    pending_devices = analytics_engine.get_pending_devices()
    whitelist = analytics_engine.get_whitelist()

    # Create device list for visualization dropdown
    all_devices = {**pending_devices, **{ip: {'device_type': analytics_engine.device_registry.get(ip, {}).get('device_type', 'Unknown')} for ip in whitelist['whitelisted_ips']}}

    devices_json = "["
    for ip, info in all_devices.items():
        status = "Whitelisted" if ip in whitelist['whitelisted_ips'] else "Pending"
        device_type = info.get('device_type', pending_devices.get(ip, {}).get('device_type', 'Unknown'))
        devices_json += f'{{ip: "{ip}", name: "{device_type} ({ip})", status: "{status}"}}, '
    devices_json = devices_json.rstrip(", ") + "]"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Pattern Analysis - Collatz Sequences</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                background: linear-gradient(135deg, #0a0e27 0%, #151d3b 100%);
                color: #e0e0e0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            .header {{
                text-align: center;
                margin-bottom: 40px;
            }}
            .header h1 {{
                color: #6496ff;
                font-size: 32px;
                margin-bottom: 10px;
            }}
            .header p {{
                color: #999;
            }}
            .controls {{
                background: rgba(15, 20, 40, 0.95);
                border: 1px solid rgba(100, 150, 255, 0.3);
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 30px;
                display: flex;
                gap: 15px;
                align-items: center;
                flex-wrap: wrap;
            }}
            .controls label {{
                color: #6496ff;
                font-weight: bold;
                margin-right: 10px;
            }}
            select {{
                background: rgba(100, 150, 255, 0.1);
                border: 1px solid #6496ff;
                color: #e0e0e0;
                padding: 10px 15px;
                border-radius: 6px;
                font-size: 14px;
                cursor: pointer;
                min-width: 200px;
            }}
            select:focus {{
                outline: none;
                box-shadow: 0 0 10px rgba(100, 150, 255, 0.5);
            }}
            .chart-container {{
                background: rgba(15, 20, 40, 0.95);
                border: 1px solid rgba(100, 150, 255, 0.3);
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 30px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
            }}
            .chart-title {{
                color: #6496ff;
                font-size: 18px;
                font-weight: bold;
                margin-bottom: 15px;
            }}
            #collatzChart {{
                max-height: 400px;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-top: 20px;
            }}
            .stat-card {{
                background: rgba(100, 150, 255, 0.1);
                border: 1px solid rgba(100, 150, 255, 0.2);
                border-radius: 8px;
                padding: 15px;
                text-align: center;
            }}
            .stat-label {{
                color: #999;
                font-size: 12px;
                margin-bottom: 8px;
            }}
            .stat-value {{
                color: #6496ff;
                font-size: 24px;
                font-weight: bold;
            }}
            .patterns {{
                background: rgba(100, 150, 255, 0.1);
                border: 1px solid rgba(100, 150, 255, 0.2);
                border-radius: 8px;
                padding: 15px;
                margin-top: 20px;
            }}
            .pattern-item {{
                padding: 10px 0;
                border-bottom: 1px solid rgba(100, 150, 255, 0.1);
            }}
            .pattern-item:last-child {{
                border-bottom: none;
            }}
            .pattern-type {{
                color: #6496ff;
                font-weight: bold;
                text-transform: capitalize;
            }}
            .pattern-confidence {{
                color: #00d084;
                font-size: 12px;
                margin-left: 10px;
            }}
            .back-btn {{
                background: rgba(100, 150, 255, 0.2);
                border: 1px solid #6496ff;
                color: #6496ff;
                padding: 10px 20px;
                border-radius: 6px;
                cursor: pointer;
                font-weight: bold;
                transition: all 0.3s ease;
            }}
            .back-btn:hover {{
                background: rgba(100, 150, 255, 0.3);
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <button class="back-btn" onclick="window.location.href='/analytics/registration/'">← Back</button>

            <div class="header">
                <h1>📊 Pattern Analysis</h1>
                <p>Collatz Sequence Visualization for Device Verification</p>
            </div>

            <div class="controls">
                <label for="deviceSelect">Select Device:</label>
                <select id="deviceSelect" onchange="loadCollatzGraph()">
                    <option value="">-- Choose a device --</option>
                </select>
            </div>

            <div class="chart-container">
                <div class="chart-title">Collatz Sequence Graph</div>
                <canvas id="collatzChart"></canvas>
            </div>

            <div id="statsContainer"></div>
        </div>

        <script>
            let chartInstance = null;
            const devices = {devices_json};

            // Populate device dropdown
            function initDevices() {{
                const select = document.getElementById('deviceSelect');
                devices.forEach(device => {{
                    const option = document.createElement('option');
                    option.value = device.ip;
                    option.textContent = device.name + ' [' + device.status + ']';
                    select.appendChild(option);
                }});
            }}

            function loadCollatzGraph() {{
                const ip = document.getElementById('deviceSelect').value;
                if (!ip) return;

                fetch(`/analytics/api/collatz/?ip=${{ip}}`)
                    .then(r => r.json())
                    .then(data => {{
                        if (!data.success) {{
                            alert('Error: ' + data.error);
                            return;
                        }}
                        drawChart(data);
                        displayStats(data);
                    }})
                    .catch(e => alert('Error loading data: ' + e));
            }}

            function drawChart(data) {{
                const ctx = document.getElementById('collatzChart').getContext('2d');

                if (chartInstance) {{
                    chartInstance.destroy();
                }}

                chartInstance = new Chart(ctx, {{
                    type: 'line',
                    data: {{
                        labels: Array.from({{length: data.sequence.length}}, (_, i) => i),
                        datasets: [{{
                            label: 'Collatz Sequence (' + data.ip + ')',
                            data: data.sequence,
                            borderColor: '#6496ff',
                            backgroundColor: 'rgba(100, 150, 255, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.3,
                            pointRadius: 0,
                            pointHoverRadius: 5
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {{
                            legend: {{
                                labels: {{ color: '#e0e0e0', font: {{ size: 12 }} }}
                            }}
                        }},
                        scales: {{
                            x: {{
                                grid: {{ color: 'rgba(100, 150, 255, 0.1)' }},
                                ticks: {{ color: '#999', maxTicksLimit: 10 }}
                            }},
                            y: {{
                                grid: {{ color: 'rgba(100, 150, 255, 0.1)' }},
                                ticks: {{ color: '#999' }}
                            }}
                        }}
                    }}
                }});
            }}

            function displayStats(data) {{
                let html = `
                    <div class="chart-container">
                        <div class="chart-title">Sequence Statistics</div>
                        <div class="stats">
                            <div class="stat-card">
                                <div class="stat-label">Sequence Length</div>
                                <div class="stat-value">${{data.length}}</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">Peak Value</div>
                                <div class="stat-value">${{data.max_value}}</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">Risk Score</div>
                                <div class="stat-value">${{(data.risk_score * 100).toFixed(1)}}%</div>
                            </div>
                        </div>`;

                if (data.patterns.length > 0) {{
                    html += `<div class="patterns">`;
                    html += `<div style="color: #6496ff; font-weight: bold; margin-bottom: 10px;">Detected Patterns</div>`;
                    data.patterns.forEach(p => {{
                        html += `
                            <div class="pattern-item">
                                <span class="pattern-type">${{p.type}}</span>
                                <span class="pattern-confidence">Confidence: ${{(p.confidence * 100).toFixed(1)}}%</span>
                                <div style="color: #999; font-size: 12px; margin-top: 5px;">
                                    Frequency: ${{p.frequency}} | Range: ${{p.min}}-${{p.max}}
                                </div>
                            </div>
                        `;
                    }});
                    html += `</div>`;
                }}

                if (data.anomalies.length > 0) {{
                    html += `
                        <div class="patterns" style="border-left: 3px solid #ff6b6b; margin-top: 20px;">
                            <div style="color: #ff6b6b; font-weight: bold; margin-bottom: 10px;">⚠️ Anomalies Detected</div>`;
                    data.anomalies.forEach(a => {{
                        html += `<div style="color: #ffb3b3; font-size: 13px; padding: 5px 0;">${{a}}</div>`;
                    }});
                    html += `</div>`;
                }}

                html += `</div>`;
                document.getElementById('statsContainer').innerHTML = html;
            }}

            // Initialize on load
            initDevices();
        </script>
    </body>
    </html>
    """
    return HttpResponse(html)


@require_http_methods(["GET"])
def get_collatz_sequence_api(request) -> JsonResponse:
    """
    API endpoint: Get Collatz sequence for a given IP address.
    Used for visualization and pattern analysis.
    """
    try:
        ip_address = request.GET.get('ip')
        if not ip_address:
            return JsonResponse({'error': 'ip parameter required'}, status=400)

        # Generate Collatz sequence from IP
        start_num = int(ip_address.split('.')[-1]) * 100
        sequence = []
        num = start_num
        max_steps = 500

        while num != 1 and len(sequence) < max_steps:
            sequence.append(num)
            if num % 2 == 0:
                num = num // 2
            else:
                num = 3 * num + 1

        sequence.append(1)  # Add final 1

        # Analyze the sequence
        analysis = analytics_engine.analyze_sequence(
            ip_address=ip_address,
            sequence=sequence,
            sequence_length=len(sequence),
            max_value=max(sequence) if sequence else 0,
            steps_to_one=len(sequence) - 1
        )

        return JsonResponse({
            'success': True,
            'ip': ip_address,
            'sequence': sequence,
            'length': len(sequence),
            'max_value': max(sequence) if sequence else 0,
            'patterns': [
                {
                    'type': p.pattern_type,
                    'frequency': p.frequency,
                    'confidence': round(p.confidence, 3),
                    'max': p.max_value,
                    'min': p.min_value
                }
                for p in analysis['patterns']
            ],
            'risk_score': round(analysis['risk_score'], 3),
            'anomalies': analysis['anomalies']
        })

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@require_http_methods(["GET", "POST"])
def admin_login_view(request):
    """
    Admin login page - Authenticate network admin.
    """
    from django.http import HttpResponse
    import json

    if request.method == 'POST':
        # Handle login submission
        try:
            data = json.loads(request.body)
            username = data.get('username', '')
            password = data.get('password', '')

            result = analytics_engine.login_admin(username, password)

            if result['success']:
                # Store session token in response
                response = JsonResponse({
                    'success': True,
                    'message': result['message'],
                    'session_token': result['session_token'],
                    'username': result['username']
                })
                response.set_cookie('admin_token', result['session_token'], max_age=28800, httponly=True)
                return response
            else:
                return JsonResponse({
                    'success': False,
                    'message': result['message']
                }, status=401)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)

    # GET - Show login form
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Login - Firewall Gateway</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                background: linear-gradient(135deg, #0a0e27 0%, #151d3b 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            .login-container {
                background: rgba(20, 25, 50, 0.95);
                border: 2px solid #4a5899;
                border-radius: 8px;
                padding: 40px;
                width: 100%;
                max-width: 400px;
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
            }
            .login-header {
                text-align: center;
                margin-bottom: 30px;
            }
            .login-header h1 {
                color: #00d4ff;
                font-size: 24px;
                margin-bottom: 10px;
            }
            .login-header p {
                color: #888;
                font-size: 12px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            .form-group label {
                display: block;
                color: #e0e0e0;
                font-size: 13px;
                margin-bottom: 8px;
                font-weight: 500;
            }
            .form-group input {
                width: 100%;
                padding: 10px;
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid #4a5899;
                border-radius: 4px;
                color: #e0e0e0;
                font-size: 13px;
            }
            .form-group input:focus {
                outline: none;
                border-color: #00d4ff;
                background: rgba(0, 212, 255, 0.05);
            }
            .login-button {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #00d4ff 0%, #0080ff 100%);
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
            }
            .login-button:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 20px rgba(0, 212, 255, 0.3);
            }
            .error-message {
                display: none;
                color: #ff4444;
                background: rgba(255, 0, 0, 0.1);
                border: 1px solid #ff4444;
                padding: 10px;
                border-radius: 4px;
                font-size: 12px;
                margin-top: 15px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <h1>🔐 Admin Login</h1>
                <p>Firewall Gateway Control Panel</p>
            </div>
            <form id="loginForm">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required placeholder="admin">
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required placeholder="••••••••">
                </div>
                <button type="submit" class="login-button">Login</button>
                <div id="errorMessage" class="error-message"></div>
            </form>
        </div>

        <script>
            document.getElementById('loginForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const errorDiv = document.getElementById('errorMessage');

                try {
                    const response = await fetch('/analytics/api/admin/login/', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCookie('csrftoken')
                        },
                        body: JSON.stringify({ username, password })
                    });

                    const result = await response.json();

                    if (result.success) {
                        // Store token and redirect
                        localStorage.setItem('admin_token', result.session_token);
                        window.location.href = '/analytics/admin/';
                    } else {
                        errorDiv.textContent = result.message;
                        errorDiv.style.display = 'block';
                    }
                } catch (error) {
                    errorDiv.textContent = 'Login failed: ' + error.message;
                    errorDiv.style.display = 'block';
                }
            });

            function getCookie(name) {
                let cookieValue = null;
                if (document.cookie && document.cookie !== '') {
                    const cookies = document.cookie.split(';');
                    for (let i = 0; i < cookies.length; i++) {
                        const cookie = cookies[i].trim();
                        if (cookie.substring(0, name.length + 1) === (name + '=')) {
                            cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                            break;
                        }
                    }
                }
                return cookieValue;
            }
        </script>
    </body>
    </html>
    """
    return HttpResponse(html)


@require_http_methods(["POST"])
@csrf_exempt
def admin_login_api(request) -> JsonResponse:
    """
    API endpoint for admin login.
    """
    try:
        data = json.loads(request.body)
        username = data.get('username', '')
        password = data.get('password', '')

        result = analytics_engine.login_admin(username, password)

        if result['success']:
            response = JsonResponse({
                'success': True,
                'message': result['message'],
                'session_token': result['session_token'],
                'username': result['username']
            })
            response.set_cookie('admin_token', result['session_token'], max_age=28800, httponly=True)
            return response
        else:
            return JsonResponse({
                'success': False,
                'message': result['message']
            }, status=401)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


def admin_panel_view(request):
    """
    Admin panel for device approval management.
    """
    import json
    from django.http import HttpResponse

    # Check admin authentication via cookie or token
    admin_token = request.COOKIES.get('admin_token')

    if not admin_token or not analytics_engine.verify_admin_session(admin_token):
        # Redirect to login if not authenticated
        return render(request, 'analytics/admin_redirect.html', {'redirect_url': '/analytics/admin/login/'})

    # Get pending devices, whitelist, stats, and active sessions
    pending_devices = analytics_engine.get_pending_devices()
    whitelist = analytics_engine.get_whitelist()
    stats = analytics_engine.get_performance_summary()
    active_sessions = analytics_engine.get_active_sessions()

    # Build pending devices list HTML
    pending_html = ""
    if pending_devices:
        for ip, info in pending_devices.items():
            pending_html += f"""
            <div class="device-card">
                <div class="device-header">
                    <span class="device-type-badge">{info.get('device_type', 'Unknown')}</span>
                    <span class="device-ip">{ip}</span>
                    <span class="status-badge pending">PENDING</span>
                </div>
                <div class="device-details">
                    <p><strong>Requested:</strong> {info.get('timestamp', 'N/A')}</p>
                    <p><strong>User Agent:</strong> <small>{info.get('user_agent', 'Unknown')[:60]}...</small></p>
                </div>
                <div class="device-actions">
                    <button class="btn-approve" onclick="approveDevice('{ip}')">✓ Approve</button>
                    <button class="btn-reject" onclick="rejectDevice('{ip}')">✗ Reject</button>
                </div>
            </div>
            """
    else:
        pending_html = '<p style="color: #888; text-align: center;">No pending devices</p>'

    # Build whitelisted devices list HTML
    whitelisted_html = ""
    if whitelist['whitelisted_ips']:
        for ip in whitelist['whitelisted_ips']:
            device_info = analytics_engine.device_registry.get(ip, {})
            # Get the SHA1-E3 hash for this IP
            whitelist_entry = whitelist['whitelist_data'].get(ip, {})
            hash_value = whitelist_entry.get('hash', 'N/A')

            # Get the Collatz sequence for this IP
            seq_info = analytics_engine.get_collatz_sequence_for_ip(ip)
            sequence = seq_info.get('sequence', []) if seq_info.get('found') else []
            sequence_display = ', '.join(str(n) for n in sequence[:10])
            if len(sequence) > 10:
                sequence_display += f", ... ({len(sequence)} total)"

            whitelisted_html += f"""
            <div class="whitelisted-item">
                <div style="flex: 1;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <span class="device-type-badge">{device_info.get('device_type', 'Unknown')}</span>
                        <span class="device-ip">{ip}</span>
                        <span class="status-badge approved">✓ APPROVED</span>
                    </div>
                    <div class="hash-display">
                        <small style="color: #00d4ff;">SHA1-E3 Hash:</small>
                        <code style="display: block; font-size: 11px; color: #4caf50; margin-top: 4px; word-break: break-all;">{hash_value}</code>
                    </div>
                    <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(76, 175, 80, 0.2);">
                        <small style="color: #00d4ff;">Collatz Sequence:</small>
                        <code style="display: block; font-size: 10px; color: #88ccff; margin-top: 4px; word-break: break-all;">{sequence_display}</code>
                    </div>
                </div>
                <button class="btn-remove" onclick="removeWhitelist('{ip}')">Remove</button>
            </div>
            """
    else:
        whitelisted_html = '<p style="color: #888; text-align: center;">No approved devices</p>'

    # Build active sessions list HTML
    active_sessions_html = ""
    if active_sessions['active_sessions']:
        for ip, session_info in active_sessions['active_sessions'].items():
            device_info = analytics_engine.device_registry.get(ip, {})
            first_access = session_info.get('first_access', 'N/A')[:19]  # Format timestamp
            last_access = session_info.get('last_access', 'N/A')[:19]
            access_count = session_info.get('access_count', 0)

            active_sessions_html += f"""
            <div class="session-card">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                    <span class="device-type-badge">{session_info.get('device_type', 'Unknown')}</span>
                    <span class="device-ip">{ip}</span>
                    <span class="status-badge approved">● ACTIVE</span>
                </div>
                <div style="color: #aaa; font-size: 11px;">
                    <p><strong>Requests:</strong> {access_count}</p>
                    <p><strong>First Access:</strong> {first_access}</p>
                    <p><strong>Last Access:</strong> {last_access}</p>
                </div>
            </div>
            """
    else:
        active_sessions_html = '<p style="color: #888; text-align: center;">No active sessions</p>'

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel - Firewall Gateway</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                background: #f3f3f3;
                color: #333;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', sans-serif;
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{
                max-width: 1400px;
                margin: 0 auto;
            }}
            .header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
                padding: 20px 30px;
                background: rgba(255, 255, 255, 0.8);
                backdrop-filter: blur(10px);
                border-radius: 12px;
                border: 1px solid rgba(0, 0, 0, 0.06);
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
            }}
            .header h1 {{
                color: #0078d4;
                font-size: 28px;
                font-weight: 600;
                letter-spacing: -0.5px;
            }}
            .header p {{
                color: #666;
                font-size: 13px;
                margin-top: 4px;
            }}
            .logout-btn {{
                background: #f3f3f3;
                color: #d13438;
                border: 1px solid #d13438;
                padding: 8px 20px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 13px;
                font-weight: 500;
                transition: all 0.2s;
            }}
            .logout-btn:hover {{
                background: #d13438;
                color: white;
                box-shadow: 0 2px 8px rgba(209, 52, 56, 0.3);
            }}
            .logout-btn:active {{
                transform: scale(0.98);
            }}
            .stats-row {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 16px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background: rgba(255, 255, 255, 0.7);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(0, 0, 0, 0.06);
                border-radius: 12px;
                padding: 24px 20px;
                text-align: center;
                transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
                cursor: pointer;
                position: relative;
                overflow: hidden;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
            }}
            .stat-card::before {{
                content: '';
                position: absolute;
                top: -50%;
                left: -50%;
                width: 200%;
                height: 200%;
                background: linear-gradient(45deg, transparent, rgba(0, 120, 212, 0.1), transparent);
                transform: rotate(45deg);
                transition: all 0.6s;
            }}
            .stat-card:hover {{
                transform: translateY(-4px);
                border-color: rgba(0, 120, 212, 0.3);
                box-shadow: 0 4px 12px rgba(0, 120, 212, 0.15);
                background: rgba(255, 255, 255, 0.9);
            }}
            .stat-card:hover::before {{
                left: 100%;
            }}
            .stat-number {{
                color: #0078d4;
                font-size: 36px;
                font-weight: 700;
                margin: 12px 0 8px;
                position: relative;
                z-index: 1;
            }}
            .stat-label {{
                color: #666;
                font-size: 13px;
                font-weight: 500;
                text-transform: none;
                letter-spacing: 0;
                position: relative;
                z-index: 1;
            }}
            .panels {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
                margin-top: 20px;
            }}
            .panel {{
                background: rgba(255, 255, 255, 0.7);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(0, 0, 0, 0.06);
                border-radius: 12px;
                padding: 24px;
                transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
            }}
            .panel:hover {{
                border-color: rgba(0, 120, 212, 0.3);
                box-shadow: 0 4px 12px rgba(0, 120, 212, 0.1);
            }}
            .panel h2 {{
                color: #0078d4;
                font-size: 18px;
                font-weight: 600;
                margin-bottom: 16px;
                padding-bottom: 12px;
                border-bottom: 1px solid rgba(0, 0, 0, 0.06);
                display: flex;
                align-items: center;
                gap: 8px;
            }}
            .device-card {{
                background: rgba(255, 255, 255, 0.5);
                border: 1px solid rgba(0, 0, 0, 0.06);
                border-radius: 8px;
                padding: 16px;
                margin-bottom: 12px;
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            }}
            .device-card:hover {{
                background: rgba(255, 255, 255, 0.8);
                border-color: rgba(0, 120, 212, 0.2);
                transform: translateX(3px);
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
            }}
            .device-header {{
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 10px;
            }}
            .device-type-badge {{
                background: #e7f0f7;
                color: #0078d4;
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 600;
            }}
            .device-ip {{
                font-weight: 600;
                color: #0078d4;
                flex: 1;
                font-size: 14px;
            }}
            .status-badge {{
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 600;
            }}
            .status-badge.pending {{
                background: #fef3cd;
                color: #856404;
            }}
            .status-badge.approved {{
                background: #d4edda;
                color: #155724;
            }},
            .status-badge.active {{
                background: #d4edda;
                color: #155724;
            }}
            .device-details {{
                color: #666;
                font-size: 12px;
                margin: 8px 0;
            }}
            .device-details small {{
                display: block;
                margin: 4px 0;
            }}
            .device-actions {{
                display: flex;
                gap: 8px;
                margin-top: 10px;
            }}
            .btn-approve, .btn-reject, .btn-remove {{
                padding: 8px 16px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 13px;
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
                font-weight: 500;
                text-transform: none;
                letter-spacing: 0;
            }}
            .btn-approve {{
                background: #107c10;
                color: white;
                border: 1px solid #107c10;
            }}
            .btn-approve:hover {{
                background: #0b6a0b;
                border-color: #0b6a0b;
                box-shadow: 0 2px 8px rgba(16, 124, 16, 0.2);
            }}
            .btn-approve:active {{
                transform: scale(0.98);
            }}
            .btn-reject {{
                background: #f7630c;
                color: white;
                border: 1px solid #f7630c;
            }}
            .btn-reject:hover {{
                background: #da5a00;
                border-color: #da5a00;
                box-shadow: 0 2px 8px rgba(247, 99, 12, 0.2);
            }}
            .btn-reject:active {{
                transform: scale(0.98);
            }}
            .btn-remove {{
                background: #d13438;
                color: white;
                margin-left: auto;
                border: 1px solid #d13438;
            }}
            .btn-remove:hover {{
                background: #a4373a;
                border-color: #a4373a;
                box-shadow: 0 2px 8px rgba(209, 52, 56, 0.2);
            }}
            .btn-remove:active {{
                transform: scale(0.98);
            }}
            .whitelisted-item {{
                display: flex;
                align-items: flex-start;
                gap: 12px;
                background: rgba(255, 255, 255, 0.5);
                border: 1px solid rgba(0, 0, 0, 0.06);
                padding: 16px;
                border-radius: 8px;
                margin-bottom: 12px;
                transition: all 0.2s;
            }}
            .whitelisted-item:hover {{
                background: rgba(255, 255, 255, 0.8);
                border-color: rgba(0, 120, 212, 0.2);
            }}
            .hash-display {{
                background: rgba(16, 124, 16, 0.08);
                padding: 12px;
                border-left: 3px solid #107c10;
                border-radius: 4px;
                margin: 10px 0;
            }}
            .hash-display small {{
                color: #107c10;
                font-weight: 600;
                font-size: 12px;
            }}
            .hash-display code {{
                background: rgba(0, 0, 0, 0.05);
                padding: 6px 8px;
                border-radius: 4px;
                font-size: 11px;
                color: #0078d4;
                font-family: 'Courier New', monospace;
            }}
            .session-card {{
                background: rgba(255, 255, 255, 0.5);
                border: 1px solid rgba(0, 0, 0, 0.06);
                border-radius: 8px;
                padding: 16px;
                margin-bottom: 12px;
                transition: all 0.2s;
            }}
            .session-card:hover {{
                background: rgba(255, 255, 255, 0.8);
                border-color: rgba(0, 120, 212, 0.2);
            }}
            .session-card p {{
                margin: 6px 0;
                font-size: 13px;
                color: #333;
            }}
            .session-card strong {{
                color: #0078d4;
                font-weight: 600;
            }}
            .message {{
                padding: 14px 16px;
                border-radius: 6px;
                margin-bottom: 20px;
                display: none;
                font-size: 13px;
                font-weight: 500;
                animation: slideDown 0.3s ease-out;
            }}
            @keyframes slideDown {{
                from {{
                    opacity: 0;
                    transform: translateY(-10px);
                }}
                to {{
                    opacity: 1;
                    transform: translateY(0);
                }}
            }}
            .message.success {{
                background: rgba(16, 124, 16, 0.1);
                border: 1px solid rgba(16, 124, 16, 0.3);
                color: #107c10;
            }}
            .message.error {{
                background: rgba(209, 52, 56, 0.1);
                border: 1px solid rgba(209, 52, 56, 0.3);
                color: #d13438;
            }}
            .footer {{
                margin-top: 50px;
                padding: 24px;
                border-top: 1px solid rgba(0, 0, 0, 0.06);
                color: #666;
                font-size: 12px;
                text-align: center;
                background: rgba(255, 255, 255, 0.3);
                border-radius: 12px;
            }}
            .system-status {{
                display: flex;
                justify-content: center;
                gap: 24px;
                margin-top: 12px;
                flex-wrap: wrap;
            }}
            .status-indicator {{
                display: flex;
                align-items: center;
                gap: 6px;
                font-size: 12px;
                color: #666;
            }}
            .status-dot {{
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: #107c10;
                animation: pulse 2s ease-in-out infinite;
                box-shadow: 0 0 6px rgba(16, 124, 16, 0.4);
            }}
            @keyframes pulse {{
                0%, 100% {{ opacity: 1; transform: scale(1); }}
                50% {{ opacity: 0.6; transform: scale(0.9); }}
            }}
            @media (max-width: 1024px) {{
                .panels {{ grid-template-columns: 1fr; }}
                .header {{ flex-direction: column; gap: 16px; text-align: center; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <h1>🔒 Admin Control Panel</h1>
                    <p style="color: #888; font-size: 12px;">Firewall Gateway Device Management</p>
                </div>
                <button class="logout-btn" onclick="logout()">Logout</button>
            </div>

            <div id="message" class="message"></div>

            <div class="stats-row">
                <div class="stat-card">
                    <div class="stat-label">Total Devices</div>
                    <div class="stat-number">{stats['total_devices']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Approved</div>
                    <div class="stat-number">{stats['whitelisted_devices']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Pending Approval</div>
                    <div class="stat-number">{stats['pending_devices']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Active Users</div>
                    <div class="stat-number">{active_sessions['count']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Total Verifications</div>
                    <div class="stat-number">{stats['total_verifications']}</div>
                </div>
            </div>

            <div class="panels">
                <div class="panel">
                    <h2>⏳ Pending Device Approvals ({len(pending_devices)})</h2>
                    {pending_html}
                </div>
                <div class="panel">
                    <h2>✓ Approved Devices ({len(whitelist['whitelisted_ips'])})</h2>
                    {whitelisted_html}
                </div>
            </div>

            <div style="margin-top: 20px;">
                <div class="panel">
                    <h2>🟢 Currently Active Service Users ({active_sessions['count']})</h2>
                    {active_sessions_html}
                </div>
            </div>

            <div class="footer">
                <p>🔐 Firewall Gateway Security System | SHA1-E3 Cryptographic Verification</p>
                <div class="system-status">
                    <div class="status-indicator">
                        <div class="status-dot"></div>
                        <span>Firewall Active</span>
                    </div>
                    <div class="status-indicator">
                        <div class="status-dot"></div>
                        <span>Verification Engine</span>
                    </div>
                    <div class="status-indicator">
                        <div class="status-dot"></div>
                        <span>Admin Panel</span>
                    </div>
                </div>
            </div>
        </div>

        <script>
            async function approveDevice(ip) {{
                if (!confirm(`Approve device ${{ip}}?`)) return;

                try {{
                    const response = await fetch('/analytics/api/admin/approve/', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCookie('csrftoken')
                        }},
                        body: JSON.stringify({{ ip_address: ip }})
                    }});

                    const result = await response.json();

                    if (result.success) {{
                        showMessage('Device approved successfully!', 'success');
                        setTimeout(() => location.reload(), 1500);
                    }} else {{
                        showMessage('Failed to approve: ' + result.message, 'error');
                    }}
                }} catch (error) {{
                    showMessage('Error: ' + error.message, 'error');
                }}
            }}

            async function rejectDevice(ip) {{
                if (!confirm(`Reject device ${{ip}}?`)) return;

                try {{
                    const response = await fetch('/analytics/api/admin/reject/', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCookie('csrftoken')
                        }},
                        body: JSON.stringify({{ ip_address: ip }})
                    }});

                    const result = await response.json();

                    if (result.success) {{
                        showMessage('Device rejected successfully!', 'success');
                        setTimeout(() => location.reload(), 1500);
                    }} else {{
                        showMessage('Failed to reject: ' + result.message, 'error');
                    }}
                }} catch (error) {{
                    showMessage('Error: ' + error.message, 'error');
                }}
            }}

            async function removeWhitelist(ip) {{
                if (!confirm(`Remove ${{ip}} from whitelist?`)) return;

                try {{
                    const response = await fetch('/analytics/api/whitelist/remove/', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCookie('csrftoken')
                        }},
                        body: JSON.stringify({{ ip_address: ip }})
                    }});

                    const result = await response.json();

                    if (result.success) {{
                        showMessage('Device removed from whitelist!', 'success');
                        setTimeout(() => location.reload(), 1500);
                    }} else {{
                        showMessage('Failed to remove: ' + result.message, 'error');
                    }}
                }} catch (error) {{
                    showMessage('Error: ' + error.message, 'error');
                }}
            }}

            function logout() {{
                if (confirm('Logout from admin panel?')) {{
                    localStorage.removeItem('admin_token');
                    window.location.href = '/analytics/admin/login/';
                }}
            }}

            function showMessage(text, type) {{
                const msgDiv = document.getElementById('message');
                msgDiv.textContent = text;
                msgDiv.className = 'message ' + type;
                msgDiv.style.display = 'block';
            }}

            function getCookie(name) {{
                let cookieValue = null;
                if (document.cookie && document.cookie !== '') {{
                    const cookies = document.cookie.split(';');
                    for (let i = 0; i < cookies.length; i++) {{
                        const cookie = cookies[i].trim();
                        if (cookie.substring(0, name.length + 1) === (name + '=')) {{
                            cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                            break;
                        }}
                    }}
                }}
                return cookieValue;
            }}

            // Auto-refresh dashboard every 30 seconds to show live updates
            setInterval(() => {{
                location.reload();
            }}, 30000);

            // Fade out message after 5 seconds
            setTimeout(() => {{
                const msgDiv = document.getElementById('message');
                if (msgDiv && msgDiv.style.display === 'block') {{
                    msgDiv.style.display = 'none';
                }}
            }}, 5000);
        </script>
    </body>
    </html>
    """
    return HttpResponse(html)


@require_http_methods(["POST"])
@csrf_exempt
def admin_approve_api(request) -> JsonResponse:
    """
    API endpoint for admin to approve a device - generates SHA1-E3 hash on approval.
    """
    try:
        # Check admin authentication
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not analytics_engine.verify_admin_session(admin_token):
            return JsonResponse({'success': False, 'message': 'Unauthorized'}, status=401)

        data = json.loads(request.body)
        ip_address = data.get('ip_address')

        if not ip_address:
            return JsonResponse({'success': False, 'message': 'IP address required'}, status=400)

        result = analytics_engine.approve_device(ip_address)

        return JsonResponse({
            'success': result['success'],
            'message': result['message'],
            'hash': result.get('hash', '')
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@require_http_methods(["POST"])
@csrf_exempt
def admin_reject_api(request) -> JsonResponse:
    """
    API endpoint for admin to reject a device.
    """
    try:
        # Check admin authentication
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not analytics_engine.verify_admin_session(admin_token):
            return JsonResponse({'success': False, 'message': 'Unauthorized'}, status=401)

        data = json.loads(request.body)
        ip_address = data.get('ip_address')

        if not ip_address:
            return JsonResponse({'success': False, 'message': 'IP address required'}, status=400)

        result = analytics_engine.reject_device(ip_address)

        return JsonResponse({
            'success': result['success'],
            'message': result['message']
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@require_http_methods(["GET"])
def get_collatz_sequence_api(request, ip_address: str) -> JsonResponse:
    """
    API endpoint to get Collatz sequence data for an IP.
    Useful for visualization and Grafana integration.
    """
    try:
        seq_info = analytics_engine.get_collatz_sequence_for_ip(ip_address)
        if seq_info.get('found'):
            return JsonResponse({
                'success': True,
                'ip': ip_address,
                'sequence': seq_info['sequence'],
                'sequence_length': seq_info['sequence_length'],
                'hash': seq_info['hash'],
                'max_value': max(seq_info['sequence']) if seq_info['sequence'] else 0,
                'min_value': min(seq_info['sequence']) if seq_info['sequence'] else 0
            })
        else:
            return JsonResponse({'success': False, 'message': 'No sequence data found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@require_http_methods(["GET"])
def get_active_sessions_api(request) -> JsonResponse:
    """
    API endpoint to get all active service user sessions.
    """
    try:
        # Check admin authentication
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not analytics_engine.verify_admin_session(admin_token):
            return JsonResponse({'success': False, 'message': 'Unauthorized'}, status=401)

        sessions = analytics_engine.get_active_sessions()
        return JsonResponse({
            'success': True,
            'active_sessions': sessions['active_sessions'],
            'count': sessions['count'],
            'total_accesses': sessions['total_accesses']
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


# ============ INTEGRATED DASHBOARD IMPORTS ============
from .views_dashboard import (
    dashboard_main,
    collatz_graphs,
    user_insights,
    api_collatz_graphs,
    api_user_insights
)


@require_http_methods(["GET"])
def api_collatz_graphs_endpoint(request):
    """API endpoint for Collatz graph data"""
    return api_collatz_graphs(request)


@require_http_methods(["GET"])
def api_user_insights_endpoint(request):
    """API endpoint for user insights data"""
    return api_user_insights(request)
