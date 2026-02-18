"""Firewall Gateway URL Configuration"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('firewall/', include('firewall_gateway.api.urls')),
    path('analytics/', include('firewall_gateway.analytics.urls')),
]
