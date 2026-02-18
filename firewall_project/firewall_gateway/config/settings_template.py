"""
Firewall Configuration Template
Copy this to your Django settings.py and customize as needed.
"""

import os
import sys

# ============================================================================
# COLLATZ FIREWALL GATEWAY SETTINGS
# ============================================================================

# Enable/Disable the firewall
COLLATZ_FIREWALL_ENABLED = True

# Hash implementation: NATIVE SHA1-E3 RUST ONLY
# Location: /sha1_e3_native/target/release/
# Speed: 500+ MB/s
# No fallbacks - native is required for production
# Status: Auto-loaded from compiled Rust binary

# Enforcement mode:
# - False: Log access attempts but don't block (audit mode)
# - True: Block non-whitelisted IPs with 403 response (enforced mode)
COLLATZ_FIREWALL_ENFORCE = False

# Log all access attempts (both allowed and blocked)
COLLATZ_FIREWALL_LOG_ALL = True

# Paths to skip firewall verification
# Add health checks, registration endpoints, admin panel, etc.
COLLATZ_FIREWALL_SKIP_PATHS = [
    '/health/',
    '/status/',
    '/firewall/register/',
    '/firewall/verify/',
    '/admin/',
    '/api-auth/',
]

# ============================================================================
# OPTIONAL: ADVANCED FIREWALL SETTINGS
# ============================================================================

# Rate limiting (optional)
COLLATZ_FIREWALL_RATE_LIMIT_ENABLED = False
COLLATZ_FIREWALL_RATE_LIMIT_REQUESTS = 100  # Requests
COLLATZ_FIREWALL_RATE_LIMIT_WINDOW = 60     # Seconds

# Logging configuration
COLLATZ_FIREWALL_LOG_LEVEL = 'INFO'  # DEBUG, INFO, WARNING, ERROR

# Performance optimization
COLLATZ_FIREWALL_CACHE_ENABLED = False      # Cache verification results
COLLATZ_FIREWALL_CACHE_TTL = 300            # Cache time-to-live (seconds)

# Security hardening
COLLATZ_FIREWALL_STRICT_MODE = False        # Reject on any error
COLLATZ_FIREWALL_REQUIRE_HTTPS = False      # Only allow HTTPS requests

# ============================================================================
# INSTALLATION CHECKLIST
# ============================================================================
"""
Follow these steps to install the Collatz Firewall:

1. Add to INSTALLED_APPS:
   INSTALLED_APPS = [
       ...
       'firewall_gateway',
   ]

2. Add to MIDDLEWARE (after SecurityMiddleware):
   MIDDLEWARE = [
       'django.middleware.security.SecurityMiddleware',
       ...
       'firewall_gateway.middleware.firewall_middleware.CollatzFirewallMiddleware',
       ...
       
   ]

3. Add firewall settings to settings.py (copy from above)

4. Add to ROOT_URLCONF (urls.py):
   urlpatterns = [
       ...
       path('firewall/', include('firewall_gateway.api.urls')),
       ...
   ]

5. Run migrations:
   python manage.py makemigrations firewall_gateway
   python manage.py migrate firewall_gateway

6. Test the installation:
   python manage.py test firewall_gateway

7. Register your IPs:
   curl -X POST http://localhost:8000/firewall/register/ \\
     -H "Content-Type: application/json" \\
     -d '{"ip_address": "127.0.0.1"}'

8. Enable in production:
   COLLATZ_FIREWALL_ENFORCE = True
"""

# ============================================================================
# DEPLOYMENT CONFIGURATIONS
# ============================================================================

# Development Configuration
FIREWALL_CONFIG_DEVELOPMENT = {
    'enabled': True,
    'enforce': False,
    'log_all': True,
    'rate_limit': False,
    'cache': False,
}

# Staging Configuration
FIREWALL_CONFIG_STAGING = {
    'enabled': True,
    'enforce': False,  # Monitor before enforcing
    'log_all': True,
    'rate_limit': False,
    'cache': True,
}

# Production Configuration
FIREWALL_CONFIG_PRODUCTION = {
    'enabled': True,
    'enforce': True,   # Actively block
    'log_all': True,
    'rate_limit': True,
    'cache': True,
    'cache_ttl': 600,
}

# Use configuration based on environment
import os
ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')

if ENVIRONMENT == 'production':
    FIREWALL_CONFIG = FIREWALL_CONFIG_PRODUCTION
elif ENVIRONMENT == 'staging':
    FIREWALL_CONFIG = FIREWALL_CONFIG_STAGING
else:
    FIREWALL_CONFIG = FIREWALL_CONFIG_DEVELOPMENT

# Apply configuration
COLLATZ_FIREWALL_ENABLED = FIREWALL_CONFIG.get('enabled', True)
COLLATZ_FIREWALL_ENFORCE = FIREWALL_CONFIG.get('enforce', False)
COLLATZ_FIREWALL_LOG_ALL = FIREWALL_CONFIG.get('log_all', True)
COLLATZ_FIREWALL_RATE_LIMIT_ENABLED = FIREWALL_CONFIG.get('rate_limit', False)
COLLATZ_FIREWALL_CACHE_ENABLED = FIREWALL_CONFIG.get('cache', False)

# ============================================================================
# MONITORING & ALERTING
# ============================================================================

# Optional: Configure alerts for suspicious activity
FIREWALL_ALERT_ENABLED = True
FIREWALL_ALERT_THRESHOLD_BLOCKED = 10      # Alert if >10 blocked in 1 minute
FIREWALL_ALERT_THRESHOLD_ERRORS = 5        # Alert if >5 errors in 1 minute
FIREWALL_ALERT_EMAIL = 'security@example.com'

# ============================================================================
# PERFORMANCE TUNING
# ============================================================================

# Database connection pooling (if using connection pooling)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'sha10_test',
        'USER': 'postgres',
        'PASSWORD': 'password',
        'HOST': 'localhost',
        'PORT': '5432',
        # Connection pooling
        'CONN_MAX_AGE': 600,
        'OPTIONS': {
            'connect_timeout': 10,
        },
    }
}

# Cache configuration for verification results (optional)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'KEY_PREFIX': 'firewall',
        'TIMEOUT': 300,
    }
}

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'firewall_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/firewall.log',
            'maxBytes': 1024 * 1024 * 10,  # 10MB
            'backupCount': 10,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'firewall_gateway': {
            'handlers': ['firewall_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# ============================================================================
# API SECURITY
# ============================================================================

# CORS configuration (if needed for cross-origin API calls)
CORS_ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'https://yourdomain.com',
]

# Rate limiting for API endpoints
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
    },
}

# ============================================================================
# TESTING CONFIGURATION
# ============================================================================

if 'test' in sys.argv:
    # Use in-memory database for tests
    DATABASES['default'] = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }

    # Disable caching for tests
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'unique-snowflake',
        }
    }

    # Disable firewall enforcement in tests
    COLLATZ_FIREWALL_ENFORCE = False
