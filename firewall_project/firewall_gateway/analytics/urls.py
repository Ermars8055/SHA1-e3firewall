"""
Analytics Dashboard URLs
"""

from django.urls import path
from . import views
from . import advanced_security_api

app_name = 'analytics'

urlpatterns = [
    # Dashboard pages
    path('', views.dashboard_view, name='dashboard'),
    path('old-dashboard/', views.AnalyticsDashboardView.as_view(), name='dashboard_page'),

    # Admin panel routes
    path('admin/login/', views.admin_login_view, name='admin_login'),
    # Unified admin panel - everything in one page
    path('admin/', views.dashboard_main, name='admin_panel'),
    path('admin/dashboard/', views.dashboard_main, name='dashboard_main'),

    # Legacy routes (now redirected to unified admin)
    path('admin/collatz-graphs/', views.dashboard_main, name='collatz_graphs'),
    path('admin/user-insights/', views.dashboard_main, name='user_insights'),
    path('admin/api/collatz-graphs/', views.api_collatz_graphs_endpoint, name='api_collatz_graphs'),
    path('admin/api/user-insights/', views.api_user_insights_endpoint, name='api_user_insights'),

    # Service pages
    path('service/', views.service_page_view, name='service'),
    path('registration/', views.registration_page_view, name='registration'),
    path('patterns/', views.patterns_page_view, name='patterns'),

    # API endpoints
    path('api/', views.get_dashboard_summary_api, name='api_summary'),
    path('api/stats/', views.get_stats_api, name='api_stats'),
    path('api/patterns/', views.get_patterns_api, name='api_patterns'),
    path('api/innovations/', views.get_innovations_api, name='api_innovations'),
    path('api/verifications/', views.get_verifications_api, name='api_verifications'),
    path('api/analyze/', views.AnalyticsAPIView.as_view(), name='api_analyze'),
    path('api/record/', views.record_verification_api, name='api_record'),
    path('api/verify/', views.verify_ip_api, name='api_verify'),
    path('api/whitelist/', views.whitelist_ip_api, name='api_whitelist'),
    path('api/whitelist/remove/', views.remove_whitelist_api, name='api_remove_whitelist'),
    path('api/whitelist/list/', views.get_whitelist_api, name='api_whitelist_list'),
    path('api/devices/', views.get_devices_api, name='api_devices'),
    path('api/network-info/', views.get_network_info_api, name='api_network_info'),
    path('api/health/', views.analytics_health_api, name='api_health'),
    path('api/approve/', views.approve_device_api, name='api_approve'),
    path('api/reject/', views.reject_device_api, name='api_reject'),
    path('api/pending/', views.get_pending_devices_api, name='api_pending'),
    path('api/collatz/<str:ip_address>/', views.get_collatz_sequence_api, name='api_collatz'),
    path('api/sessions/', views.get_active_sessions_api, name='api_sessions'),

    # Admin API endpoints
    path('api/admin/login/', views.admin_login_api, name='api_admin_login'),
    path('api/admin/approve/', views.admin_approve_api, name='api_admin_approve'),
    path('api/admin/reject/', views.admin_reject_api, name='api_admin_reject'),

    # ========== ADVANCED SECURITY ENDPOINTS ==========
    # MFA endpoints
    path('api/security/mfa/challenge/', advanced_security_api.create_mfa_challenge_api, name='api_mfa_challenge'),
    path('api/security/mfa/verify/', advanced_security_api.verify_mfa_challenge_api, name='api_mfa_verify'),

    # Rate limiting endpoints
    path('api/security/rate-limit/', advanced_security_api.check_rate_limit_api, name='api_rate_limit'),

    # Anomaly detection endpoints
    path('api/security/anomaly-detection/', advanced_security_api.detect_anomalies_api, name='api_anomaly_detection'),
    path('api/security/device-profile/', advanced_security_api.get_device_security_profile_api, name='api_device_profile'),

    # Audit logging endpoints
    path('api/security/audit/log/', advanced_security_api.log_audit_entry_api, name='api_audit_log'),
    path('api/security/audit/verify/', advanced_security_api.verify_audit_integrity_api, name='api_audit_verify'),
    path('api/security/audit/logs/', advanced_security_api.get_audit_logs_api, name='api_audit_logs'),

    # Geo-blocking endpoints
    path('api/security/geo-blocking/enable/', advanced_security_api.enable_geo_blocking_api, name='api_geo_blocking'),

    # Security dashboard
    path('api/security/dashboard/', advanced_security_api.get_security_dashboard_api, name='api_security_dashboard'),

    # ========== SHA1-E3 ADMIN SESSION ENDPOINTS ==========
    # Session verification and chain integrity checking
    path('api/security/admin/session/verify/', advanced_security_api.verify_admin_session_chain_api, name='api_admin_session_verify'),
    path('api/security/admin/session/info/', advanced_security_api.get_admin_session_info_api, name='api_admin_session_info'),
]
