from django.urls import path, include

urlpatterns = [
    path('api/', include('firewall_gateway.api.urls')),
]
