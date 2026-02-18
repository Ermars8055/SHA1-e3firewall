"""
Firewall API URL Configuration
Maps API endpoints to view functions.
"""

from django.urls import path
from . import firewall_views

app_name = 'firewall_api'

urlpatterns = [
    # Registration and verification
    path('register/', firewall_views.register_ip, name='register_ip'),
    path('verify/', firewall_views.verify_ip, name='verify_ip'),

    # Management
    path('whitelist/', firewall_views.list_whitelisted_ips, name='list_whitelisted'),
    path('deactivate/', firewall_views.deactivate_ip, name='deactivate_ip'),

    # Statistics
    path('stats/', firewall_views.firewall_stats, name='firewall_stats'),
]
