# Collatz Firewall: Quick Start Guide

Get the firewall running in 5 minutes.

## Step 1: Database Setup

```bash
cd /Users/admin/Desktop/SHA10-Test/securehash_project

# Create migrations
python manage.py makemigrations firewall_gateway

# Apply migrations
python manage.py migrate firewall_gateway
```

## Step 2: Update Django Settings

Edit `securehash_project/settings.py`:

```python
INSTALLED_APPS = [
    # ... existing apps ...
    'firewall_gateway',
]

MIDDLEWARE = [
    # ... existing middleware ...
    'firewall_gateway.middleware.firewall_middleware.CollatzFirewallMiddleware',
]

# Firewall settings
COLLATZ_FIREWALL_ENABLED = True
COLLATZ_FIREWALL_ENFORCE = False  # Set True to block non-whitelisted
COLLATZ_FIREWALL_LOG_ALL = True
COLLATZ_FIREWALL_SKIP_PATHS = [
    '/health/',
    '/firewall/register/',
    '/firewall/verify/',
    '/admin/',
]
```

## Step 3: Update URLs

Edit `securehash_project/urls.py`:

```python
urlpatterns = [
    # ... existing patterns ...
    path('firewall/', include('firewall_gateway.api.urls')),
]
```

## Step 4: Start the Server

```bash
python manage.py runserver 0.0.0.0:8000
```

## Step 5: Register an IP

```bash
# Register your local machine
curl -X POST http://localhost:8000/firewall/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "127.0.0.1",
    "name": "Local Development"
  }'
```

Expected response:
```json
{
    "success": true,
    "ip_address": "127.0.0.1",
    "collatz_hash": "9f3a7c2e1b5d8f4a2c5e7g9i...",
    "sequence_length": 156,
    "whitelist_id": 1,
    "message": "IP registered successfully"
}
```

## Step 6: Verify Access

```bash
curl -X POST http://localhost:8000/firewall/verify/ \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "127.0.0.1"}'
```

Expected response:
```json
{
    "allowed": true,
    "ip_address": "127.0.0.1",
    "hash_value": "9f3a7c2e1b5d8f4a2c5e7g9i...",
    "sequence_length": 156,
    "response_time_ms": 2.34,
    "message": "Access allowed"
}
```

## Step 7: View Statistics

```bash
curl http://localhost:8000/firewall/stats/
```

---

## Common Operations

### Register Multiple IPs

```python
from firewall_gateway.core.firewall_engine import FirewallEngine

engine = FirewallEngine()

ips = [
    '192.168.1.100',
    '192.168.1.101',
    '10.0.0.50',
]

for ip in ips:
    result = engine.register_ip(ip, name=f'Server-{ip.split(".")[-1]}')
    print(result)
```

### Check Whitelist

```bash
curl http://localhost:8000/firewall/whitelist/
```

### Deactivate an IP

```bash
curl -X POST http://localhost:8000/firewall/deactivate/ \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100"}'
```

### Monitor Access Logs

```python
from firewall_gateway.models.firewall_models import AccessLog

# Recent blocked attempts
blocked = AccessLog.objects.filter(status='blocked').order_by('-timestamp')[:10]
for log in blocked:
    print(f"{log.timestamp}: {log.ip_address} - {log.error_message}")

# Access statistics
from django.db.models import Count
by_status = AccessLog.objects.values('status').annotate(count=Count('id'))
for stat in by_status:
    print(f"{stat['status']}: {stat['count']} attempts")
```

---

## Testing

```bash
# Run all tests
python manage.py test firewall_gateway

# Run specific test class
python manage.py test firewall_gateway.tests.test_firewall_engine.TestFirewallEngine

# Run with verbose output
python manage.py test firewall_gateway -v 2
```

---

## Enable Enforcement

Once you've registered your production IPs, enable enforcement:

```python
# settings.py
COLLATZ_FIREWALL_ENFORCE = True  # Now non-whitelisted IPs get 403
```

Non-whitelisted IPs will receive:
```json
{
    "error": "IP not whitelisted"
}
```

---

## Troubleshooting

**Issue**: ImportError for firewall_gateway
- Make sure it's in INSTALLED_APPS in settings.py

**Issue**: Migration errors
- Run: `python manage.py migrate firewall_gateway --fake-initial`

**Issue**: All requests blocked
- Set COLLATZ_FIREWALL_ENFORCE = False to debug
- Check AccessLog table for error messages

**Issue**: Slow verification
- Check: Is database responding quickly?
- Check: Are Collatz sequences very long? (unlikely but possible)

---

## Next Steps

1. Review [FIREWALL_GUIDE.md](FIREWALL_GUIDE.md) for detailed documentation
2. Set up monitoring on AccessLog table
3. Configure rate limiting rules
4. Enable HTTPS for API endpoints
5. Set up log archival for compliance

---

**Ready to secure your network with mathematical chaos!** 🔐
