"""
Firewall Database Models: Django ORM models for Collatz Firewall
Stores allowed IPs, hashes, access logs, and firewall rules.
"""

from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
import ipaddress


class IPWhitelist(models.Model):
    """
    Stores allowed IP addresses with their Collatz-based hashes.

    This is the core security model of the Collatz Firewall.
    Only the hash is stored - the actual IP is stored for reference but
    all verification uses the hash computed from Collatz sequence.
    """

    ip_address = models.GenericIPAddressField(
        protocol='IPv4',
        unique=True,
        help_text="IPv4 address to whitelist"
    )

    ip_integer = models.BigIntegerField(
        validators=[
            MinValueValidator(0),
            MaxValueValidator(2**32 - 1)
        ],
        help_text="Integer representation of IP address"
    )

    collatz_hash = models.CharField(
        max_length=256,
        unique=True,
        db_index=True,
        help_text="SHA1-E3 hash of Collatz sequence"
    )

    collatz_sequence_length = models.IntegerField(
        validators=[MinValueValidator(1)],
        help_text="Length of Collatz sequence generated from IP"
    )

    collatz_steps_to_one = models.IntegerField(
        validators=[MinValueValidator(0)],
        help_text="Number of steps to reach 1 in Collatz sequence"
    )

    collatz_max_value = models.BigIntegerField(
        validators=[MinValueValidator(0)],
        help_text="Maximum value reached in Collatz sequence"
    )

    name = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Human-readable name for this IP (e.g., 'Production Server')"
    )

    description = models.TextField(
        blank=True,
        null=True,
        help_text="Description of why this IP is whitelisted"
    )

    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Whether this IP is currently allowed"
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When this IP was added to whitelist"
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Last time this entry was modified"
    )

    last_verified = models.DateTimeField(
        blank=True,
        null=True,
        help_text="Last time this IP successfully connected"
    )

    access_count = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text="Number of successful access attempts"
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'IP Whitelist Entry'
        verbose_name_plural = 'IP Whitelist Entries'
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['collatz_hash']),
            models.Index(fields=['is_active']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.name or self.ip_address} ({self.ip_address})"

    def update_access_timestamp(self):
        """Update last verified timestamp and increment access count."""
        self.last_verified = timezone.now()
        self.access_count += 1
        self.save(update_fields=['last_verified', 'access_count'])

    def deactivate(self):
        """Deactivate this whitelist entry."""
        self.is_active = False
        self.save(update_fields=['is_active'])

    def activate(self):
        """Activate this whitelist entry."""
        self.is_active = True
        self.save(update_fields=['is_active'])


class AccessLog(models.Model):
    """
    Logs all access attempts (allowed and blocked).

    Used for security auditing and rate limiting analysis.
    """

    STATUS_ALLOWED = 'allowed'
    STATUS_BLOCKED = 'blocked'
    STATUS_INVALID = 'invalid'

    STATUS_CHOICES = [
        (STATUS_ALLOWED, 'Access Allowed'),
        (STATUS_BLOCKED, 'Access Blocked'),
        (STATUS_INVALID, 'Invalid IP Format'),
    ]

    ip_address = models.GenericIPAddressField(
        protocol='IPv4',
        db_index=True,
        help_text="IP address that attempted connection"
    )

    computed_hash = models.CharField(
        max_length=256,
        blank=True,
        null=True,
        help_text="Hash computed from incoming IP's Collatz sequence"
    )

    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        db_index=True,
        help_text="Whether access was allowed or blocked"
    )

    matched_whitelist = models.ForeignKey(
        IPWhitelist,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='access_logs',
        help_text="Whitelist entry that matched (if allowed)"
    )

    user_agent = models.CharField(
        max_length=512,
        blank=True,
        null=True,
        help_text="HTTP User-Agent header"
    )

    request_path = models.CharField(
        max_length=1024,
        blank=True,
        null=True,
        help_text="HTTP request path"
    )

    request_method = models.CharField(
        max_length=10,
        blank=True,
        null=True,
        help_text="HTTP method (GET, POST, etc)"
    )

    error_message = models.TextField(
        blank=True,
        null=True,
        help_text="Error details if access was blocked"
    )

    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="When the access attempt occurred"
    )

    response_time_ms = models.IntegerField(
        blank=True,
        null=True,
        validators=[MinValueValidator(0)],
        help_text="Time taken to verify access in milliseconds"
    )

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Access Log'
        verbose_name_plural = 'Access Logs'
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['status', 'timestamp']),
            models.Index(fields=['timestamp']),
        ]

    def __str__(self):
        return f"{self.ip_address} - {self.status} - {self.timestamp}"


class FirewallRule(models.Model):
    """
    Configurable firewall rules for advanced access control.

    Allows whitelisting entire subnets or implementing rate limiting.
    """

    RULE_TYPE_ALLOW = 'allow'
    RULE_TYPE_BLOCK = 'block'
    RULE_TYPE_RATE_LIMIT = 'rate_limit'

    RULE_TYPE_CHOICES = [
        (RULE_TYPE_ALLOW, 'Allow'),
        (RULE_TYPE_BLOCK, 'Block'),
        (RULE_TYPE_RATE_LIMIT, 'Rate Limit'),
    ]

    name = models.CharField(
        max_length=255,
        help_text="Name of the firewall rule"
    )

    description = models.TextField(
        blank=True,
        null=True,
        help_text="Description of what this rule does"
    )

    rule_type = models.CharField(
        max_length=20,
        choices=RULE_TYPE_CHOICES,
        help_text="Type of firewall rule"
    )

    ip_range = models.CharField(
        max_length=100,
        help_text="IP range (CIDR notation) or single IP"
    )

    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Whether this rule is currently enforced"
    )

    priority = models.IntegerField(
        default=0,
        help_text="Rules with higher priority are evaluated first"
    )

    rate_limit_requests = models.IntegerField(
        blank=True,
        null=True,
        validators=[MinValueValidator(1)],
        help_text="For rate_limit rules: max requests allowed"
    )

    rate_limit_window_seconds = models.IntegerField(
        blank=True,
        null=True,
        validators=[MinValueValidator(1)],
        help_text="For rate_limit rules: time window in seconds"
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When this rule was created"
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Last time this rule was modified"
    )

    class Meta:
        ordering = ['-priority', 'name']
        verbose_name = 'Firewall Rule'
        verbose_name_plural = 'Firewall Rules'

    def get_rule_type_display(self) -> str:
        """Get human-readable display value for rule_type field."""
        # This method is auto-generated by Django for choice fields
        # Explicitly defining it here for type checking purposes
        return dict(self.RULE_TYPE_CHOICES).get(self.rule_type, self.rule_type)

    def __str__(self):
        return f"{self.name} ({self.get_rule_type_display()})"


class FirewallStats(models.Model):
    """
    Aggregated statistics about firewall activity.

    Helps with performance monitoring and security analysis.
    """

    date = models.DateField(
        auto_now_add=True,
        unique=True,
        db_index=True,
        help_text="Date of the statistics"
    )

    total_requests = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text="Total access attempts on this date"
    )

    allowed_requests = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text="Allowed access attempts"
    )

    blocked_requests = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text="Blocked access attempts"
    )

    invalid_requests = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text="Invalid IP format attempts"
    )

    unique_ips = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        help_text="Number of unique IP addresses"
    )

    avg_response_time_ms = models.FloatField(
        blank=True,
        null=True,
        validators=[MinValueValidator(0)],
        help_text="Average verification response time"
    )

    last_updated = models.DateTimeField(
        auto_now=True,
        help_text="Last time statistics were updated"
    )

    class Meta:
        ordering = ['-date']
        verbose_name = 'Firewall Statistics'
        verbose_name_plural = 'Firewall Statistics'

    def __str__(self):
        return f"Stats for {self.date}"

    @property
    def block_rate(self):
        """Calculate percentage of blocked requests."""
        if self.total_requests == 0:
            return 0.0
        return (self.blocked_requests / self.total_requests) * 100

    @property
    def allow_rate(self):
        """Calculate percentage of allowed requests."""
        if self.total_requests == 0:
            return 0.0
        return (self.allowed_requests / self.total_requests) * 100
