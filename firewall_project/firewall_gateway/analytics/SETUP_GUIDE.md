# Analytics Dashboard - Setup & Integration Guide

## 🚀 Quick Start

### Step 1: Add Analytics to Django Settings

```python
# In your Django settings.py

INSTALLED_APPS = [
    # ... other apps ...
    'firewall_gateway',
    'firewall_gateway.analytics',  # Add this
]

# Optional: Configure analytics behavior
ANALYTICS_CONFIG = {
    'enabled': True,
    'update_interval_ms': 2000,
    'history_limit': 100,
    'auto_deep_analysis': True,  # Analyze suspicious IPs automatically
}
```

### Step 2: Include Analytics URLs

```python
# In your main urls.py

from django.urls import path, include

urlpatterns = [
    # ... other URLs ...
    path('firewall/', include('firewall_gateway.api.urls')),
    path('firewall/analytics/', include('firewall_gateway.analytics.urls')),
]
```

### Step 3: Create Required Directories

```bash
mkdir -p securehash_project/firewall_gateway/analytics/static
mkdir -p securehash_project/firewall_gateway/analytics/templates/analytics
```

### Step 4: Run Migrations

```bash
python manage.py migrate firewall_gateway
# Note: Analytics doesn't have database models, no migration needed
```

### Step 5: Access Dashboard

```
http://localhost:8000/firewall/analytics/
```

---

## 📂 File Checklist

Verify all analytics files are in place:

```
securehash_project/firewall_gateway/analytics/
├── ✅ __init__.py
├── ✅ analytics_engine.py         (~400 lines, pattern analysis)
├── ✅ views.py                    (~200 lines, API endpoints)
├── ✅ urls.py                     (~20 lines, URL routing)
│
├── static/
│   ├── ✅ dashboard.css           (~400 lines, Windows 7 styling)
│   └── ✅ dashboard.js            (~300 lines, real-time updates)
│
├── templates/
│   └── analytics/
│       └── ✅ dashboard.html      (~300 lines, main interface)
│
├── ✅ ANALYTICS_GUIDE.md          (Complete feature documentation)
└── ✅ SETUP_GUIDE.md              (This file)
```

---

## 🔌 Integration Methods

### Method 1: Automatic Integration (Recommended)

The analytics engine is **automatically called during verification** if you follow the standard firewall pattern:

```python
# In firewall_engine.py or middleware
from firewall_gateway.analytics.analytics_engine import AnalyticsEngine

analytics_engine = AnalyticsEngine()  # Global instance

# After each verification
analytics_engine.update_performance_metrics(
    verification_time_ms=response_time_ms,
    was_allowed=was_allowed
)

# After analyzing a sequence
analysis = analytics_engine.analyze_sequence(
    ip_address=ip,
    sequence=collatz_sequence,
    sequence_length=len(collatz_sequence),
    max_value=max(collatz_sequence),
    steps_to_one=steps_to_one
)
```

### Method 2: Manual API Calls

Use the REST API to record events externally:

```bash
# Record a verification event
curl -X POST http://localhost:8000/firewall/analytics/api/record/ \
  -H "Content-Type: application/json" \
  -d '{
    "verification_time_ms": 2.5,
    "was_allowed": true
  }'

# Analyze a sequence
curl -X POST http://localhost:8000/firewall/analytics/api/ \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.1",
    "sequence": [256, 128, 64, 32, 16, 8, 4, 2, 1],
    "sequence_length": 9,
    "max_value": 256,
    "steps_to_one": 8
  }?action=analyze'
```

### Method 3: Programmatic Integration

Use the analytics engine in your custom code:

```python
from firewall_gateway.analytics.analytics_engine import AnalyticsEngine

# Create instance
analytics = AnalyticsEngine()

# Analyze single sequence
analysis = analytics.analyze_sequence(
    ip_address='192.168.1.1',
    sequence=[1, 2, 1, 2, 1],
    sequence_length=5,
    max_value=2,
    steps_to_one=4
)

# Check results
print(f"Risk Score: {analysis['risk_score']}")
print(f"Suspicious: {analysis['is_suspicious']}")
print(f"Patterns: {[p.pattern_type for p in analysis['patterns']]}")
print(f"Anomalies: {analysis['anomalies']}")

# Get summary statistics
patterns = analytics.get_pattern_summary()
print(f"Pattern Summary: {patterns}")

# Get improvement suggestions
suggestions = analytics.get_innovation_suggestions()
for sugg in suggestions:
    print(f"[{sugg.impact}] {sugg.title}: {sugg.estimated_benefit}")

# Get performance metrics
stats = analytics.get_performance_summary()
print(f"Total verifications: {stats['total_verifications']}")
print(f"Allow rate: {stats['allow_rate_percent']:.1f}%")
print(f"Avg time: {stats['avg_verification_time_ms']:.2f}ms")
```

---

## 🎯 Usage Scenarios

### Scenario 1: Real-Time Monitoring

Monitor the dashboard while the firewall is running:

```bash
# Terminal 1: Start Django server
python manage.py runserver

# Terminal 2: Generate firewall traffic
for i in {1..100}; do
    curl http://localhost:8000/firewall/verify/ \
      -d "{\"ip_address\": \"192.168.1.$((i%254+1))\"}"
    sleep 0.1
done

# Terminal 3: Watch dashboard
# Open http://localhost:8000/firewall/analytics/ in browser
# Watch stats update in real-time
```

### Scenario 2: Batch Analysis

Analyze multiple IPs and their patterns:

```python
from firewall_gateway.analytics.analytics_engine import AnalyticsEngine
from firewall_gateway.core.collatz_converter import CollatzConverter
from firewall_gateway.core.sha1e3_integrator import SHA1E3Integrator

analytics = AnalyticsEngine()
converter = CollatzConverter()

ips_to_analyze = [
    '192.168.1.1',
    '192.168.1.2',
    '10.0.0.1',
    '172.16.0.1',
]

for ip in ips_to_analyze:
    # Convert IP to sequence
    collatz = converter.convert_ip_to_collatz(ip)

    # Analyze
    analysis = analytics.analyze_sequence(
        ip_address=ip,
        sequence=collatz.sequence,
        sequence_length=collatz.sequence_length,
        max_value=collatz.max_value,
        steps_to_one=collatz.steps_to_one
    )

    # Report
    print(f"\n{ip}:")
    print(f"  Risk: {analysis['risk_score']:.2f}")
    print(f"  Anomalies: {len(analysis['anomalies'])}")
    print(f"  Patterns: {[p.pattern_type for p in analysis['patterns']]}")

# Get global insights
patterns = analytics.get_pattern_summary()
print(f"\nGlobal Patterns: {patterns}")
```

### Scenario 3: Alerting on Anomalies

Set up automated alerts for suspicious activity:

```python
from firewall_gateway.analytics.analytics_engine import AnalyticsEngine

analytics = AnalyticsEngine()

def check_and_alert(ip_address, sequence_data):
    """Check IP and alert if suspicious."""

    analysis = analytics.analyze_sequence(
        ip_address=ip_address,
        sequence=sequence_data['sequence'],
        sequence_length=sequence_data['length'],
        max_value=sequence_data['max_value'],
        steps_to_one=sequence_data['steps']
    )

    if analysis['is_suspicious']:
        # Alert level based on risk score
        if analysis['risk_score'] > 0.8:
            send_alert(f"CRITICAL: {ip_address} suspicious (risk={analysis['risk_score']:.2f})")
            block_ip(ip_address)
        elif analysis['risk_score'] > 0.5:
            send_alert(f"WARNING: {ip_address} anomalies detected")
            log_suspicious(ip_address)

    return analysis
```

### Scenario 4: Performance Tracking

Track system performance over time:

```python
import json
from datetime import datetime
from firewall_gateway.analytics.analytics_engine import AnalyticsEngine

analytics = AnalyticsEngine()
performance_log = []

def log_performance():
    """Log performance metrics periodically."""
    stats = analytics.get_performance_summary()

    entry = {
        'timestamp': str(datetime.now()),
        'total_verifications': stats['total_verifications'],
        'allow_rate': stats['allow_rate_percent'],
        'avg_time_ms': stats['avg_verification_time_ms'],
        'unique_ips': stats['total_unique_ips'],
        'suspicious_ips': stats['suspicious_ips']
    }

    performance_log.append(entry)

    # Save to file
    with open('performance_log.json', 'w') as f:
        json.dump(performance_log, f, indent=2)

    return entry

# Call periodically (e.g., every 5 minutes)
for i in range(100):
    # ... firewall operations ...
    log_performance()
    time.sleep(300)  # 5 minutes
```

---

## 🌐 API Reference Quick

| Endpoint | Method | Purpose |
|---|---|---|
| `/firewall/analytics/` | GET | Dashboard UI |
| `/firewall/analytics/api/` | GET | All dashboard data |
| `/firewall/analytics/api/stats/` | GET | Current statistics |
| `/firewall/analytics/api/patterns/` | GET | Detected patterns |
| `/firewall/analytics/api/innovations/` | GET | Suggestions |
| `/firewall/analytics/api/analyze/` | POST | Analyze sequence |
| `/firewall/analytics/api/record/` | POST | Record event |
| `/firewall/analytics/api/health/` | GET | Service health |

---

## 🔧 Advanced Configuration

### Custom Analytics Engine

Extend the analytics engine for specialized behavior:

```python
from firewall_gateway.analytics.analytics_engine import AnalyticsEngine

class CustomAnalyticsEngine(AnalyticsEngine):
    """Extended analytics with custom patterns."""

    def _detect_patterns(self, sequence):
        """Override to add custom pattern detection."""

        patterns = super()._detect_patterns(sequence)

        # Add custom pattern: "Fibonacci-like"
        if self._is_fibonacci_like(sequence):
            patterns.append(SequencePattern(
                pattern_type='fibonacci_like',
                frequency=len(sequence),
                average_length=len(sequence),
                max_value=max(sequence),
                min_value=min(sequence),
                confidence=0.70
            ))

        return patterns

    def _is_fibonacci_like(self, sequence):
        """Detect Fibonacci-like sequences."""
        if len(sequence) < 3:
            return False

        for i in range(2, len(sequence)):
            if sequence[i] != sequence[i-1] + sequence[i-2]:
                return False

        return True
```

### Performance Tuning

For high-throughput deployments:

```python
# In settings.py
ANALYTICS_CONFIG = {
    # Reduce memory usage
    'max_history_entries': 500,  # Default 1000
    'max_sequences_cached': 100,  # Default 200

    # Reduce computation
    'pattern_detection_interval': 5,  # Only analyze every 5th sequence
    'deep_analysis_threshold': 0.7,  # Only deep analyze high-risk

    # Batch processing
    'batch_analysis_size': 100,
    'async_suggestions': True,  # Generate suggestions in background
}
```

---

## 🐛 Troubleshooting

### Analytics Not Showing Data

**Problem**: Dashboard shows zeros for all metrics

**Solution**:
1. Check if firewall is receiving traffic
2. Verify analytics_engine is being called
3. Ensure JavaScript is polling correctly

```python
# Add debug logging
from firewall_gateway.analytics import analytics_engine
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('analytics')

# Patch to log calls
original_analyze = analytics_engine.analyze_sequence
def logged_analyze(*args, **kwargs):
    logger.debug(f"Analyzing: {kwargs.get('ip_address')}")
    return original_analyze(*args, **kwargs)

analytics_engine.analyze_sequence = logged_analyze
```

### Slow Dashboard

**Problem**: Dashboard updates are slow or unresponsive

**Solution**:
1. Reduce update interval (default 2000ms)
2. Limit historical data kept in memory
3. Use production-mode Django (faster)

```python
# Adjust update interval in dashboard.js
Dashboard.config.updateInterval = 5000;  // 5 seconds instead of 2

# Or in HTML
<input type="checkbox" id="auto-refresh" checked>
```

### High Memory Usage

**Problem**: Analytics engine consuming too much RAM

**Solution**:
1. Clear old sequence history
2. Reduce caching limits
3. Implement periodic cleanup

```python
# Periodic cleanup
import schedule
import time

def cleanup_old_data():
    # Keep only last 100 sequences per IP
    for ip in analytics.sequence_history:
        analytics.sequence_history[ip] = \
            analytics.sequence_history[ip][-100:]

schedule.every(1).hour.do(cleanup_old_data)

while True:
    schedule.run_pending()
    time.sleep(60)
```

---

## 📊 Data Export

### Export to CSV

```python
import csv
from datetime import datetime

analytics = AnalyticsEngine()
stats = analytics.get_performance_summary()

with open('analytics_export.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=stats.keys())
    writer.writeheader()
    writer.writerow(stats)
```

### Export to JSON

```python
import json
from firewall_gateway.analytics.analytics_engine import AnalyticsEngine

analytics = AnalyticsEngine()

export_data = {
    'stats': analytics.get_performance_summary(),
    'patterns': analytics.get_pattern_summary(),
    'suggestions': [
        {
            'title': s.title,
            'impact': s.impact,
            'benefit': s.estimated_benefit
        }
        for s in analytics.get_innovation_suggestions()
    ]
}

with open('analytics_export.json', 'w') as f:
    json.dump(export_data, f, indent=2)
```

---

## ✅ Deployment Checklist

- [ ] Analytics module added to INSTALLED_APPS
- [ ] URLs included in main urls.py
- [ ] Static files directory created
- [ ] Templates directory created
- [ ] Dashboard accessible at `/firewall/analytics/`
- [ ] API endpoints responding with data
- [ ] Auto-refresh toggle working
- [ ] Browser console free of errors
- [ ] Analytics being called from firewall core
- [ ] Performance acceptable (<100ms API response)

---

## 🎓 Learning Resources

### Understanding Collatz Sequences

- [Collatz Conjecture - Wikipedia](https://en.wikipedia.org/wiki/Collatz_conjecture)
- [The Unsolved Puzzle of Collatz](https://www.youtube.com/watch?v=xo9_4Cwyxa8)

### Analytics Patterns

- [Anomaly Detection Techniques](https://en.wikipedia.org/wiki/Anomaly_detection)
- [Time Series Analysis](https://en.wikipedia.org/wiki/Time_series)

### Django Integration

- [Django REST Framework](https://www.django-rest-framework.org/)
- [Django Class-Based Views](https://docs.djangoproject.com/en/stable/topics/class-based-views/)

---

## 📞 Support

For issues or questions:

1. Check ANALYTICS_GUIDE.md for detailed feature documentation
2. Review API examples in this guide
3. Check browser console for JavaScript errors
4. Enable DEBUG mode for detailed logging
5. Review Django logs for backend errors

---

**Analytics Dashboard Setup Complete!** ✨

Your Collatz Firewall now has full real-time monitoring and intelligence capabilities.

---

*Last Updated: December 2025*
*Version: 1.0.0*
