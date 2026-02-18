"""
Django Admin Configuration for Firewall Gateway
Registers all firewall models for admin interface access
"""

from django.contrib import admin
from .models import IPWhitelist, AccessLog, FirewallRule, FirewallStats


@admin.register(IPWhitelist)
class IPWhitelistAdmin(admin.ModelAdmin):
    """Admin interface for IP Whitelist"""
    list_display = ('ip_address', 'name', 'is_active', 'access_count', 'last_verified', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('ip_address', 'name', 'collatz_hash')
    readonly_fields = ('collatz_hash', 'ip_integer', 'collatz_sequence_length', 'collatz_steps_to_one', 'collatz_max_value', 'created_at', 'updated_at')

    fieldsets = (
        ('IP Information', {
            'fields': ('ip_address', 'ip_integer', 'name', 'description', 'is_active')
        }),
        ('Collatz Hash Data', {
            'fields': ('collatz_hash', 'collatz_sequence_length', 'collatz_steps_to_one', 'collatz_max_value'),
            'classes': ('collapse',)
        }),
        ('Access Information', {
            'fields': ('access_count', 'last_verified'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_readonly_fields(self, request, obj=None):
        """Make IP-related fields read-only"""
        if obj:
            return self.readonly_fields + ('ip_address', 'ip_integer')
        return self.readonly_fields


@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    """Admin interface for Access Logs"""
    list_display = ('ip_address', 'status', 'timestamp', 'response_time_ms')
    list_filter = ('status', 'timestamp')
    search_fields = ('ip_address', 'error_message', 'user_agent')
    readonly_fields = ('ip_address', 'status', 'timestamp', 'response_time_ms', 'error_message', 'user_agent', 'request_method', 'request_path')

    fieldsets = (
        ('Request Information', {
            'fields': ('ip_address', 'request_method', 'request_path', 'user_agent')
        }),
        ('Response Status', {
            'fields': ('status', 'response_time_ms', 'error_message')
        }),
        ('Timestamp', {
            'fields': ('timestamp',)
        }),
    )

    def has_add_permission(self, request):
        """Prevent manual creation of access logs"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Prevent deletion of access logs"""
        return False


@admin.register(FirewallRule)
class FirewallRuleAdmin(admin.ModelAdmin):
    """Admin interface for Firewall Rules"""
    list_display = ('name', 'rule_type', 'ip_range', 'is_active', 'priority')
    list_filter = ('is_active', 'rule_type')
    search_fields = ('name', 'description', 'ip_range')

    fieldsets = (
        ('Rule Information', {
            'fields': ('name', 'description', 'rule_type', 'ip_range')
        }),
        ('Configuration', {
            'fields': ('is_active', 'priority', 'rate_limit_requests', 'rate_limit_window_seconds')
        }),
    )


@admin.register(FirewallStats)
class FirewallStatsAdmin(admin.ModelAdmin):
    """Admin interface for Firewall Statistics"""
    list_display = ('date', 'total_requests', 'allowed_requests', 'blocked_requests', 'avg_response_time_ms')
    list_filter = ('date',)
    readonly_fields = ('date', 'total_requests', 'allowed_requests', 'blocked_requests', 'avg_response_time_ms', 'unique_ips', 'invalid_requests')

    fieldsets = (
        ('Statistics', {
            'fields': ('date', 'total_requests', 'allowed_requests', 'blocked_requests', 'invalid_requests', 'unique_ips')
        }),
        ('Performance', {
            'fields': ('avg_response_time_ms',)
        }),
    )

    def has_add_permission(self, request):
        """Prevent manual creation of stats"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Prevent deletion of stats"""
        return False
