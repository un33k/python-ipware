"""Default header precedence for the modern engine.

Superset of the v3 list, adding widely-deployed CDN/edge headers. Order is
most-to-least trustworthy for a typical deployment; the first header that
yields a usable IP wins.
"""

DEFAULT_PRECEDENCE: tuple[str, ...] = (
    "X_FORWARDED_FOR",
    "HTTP_X_FORWARDED_FOR",
    "HTTP_CLIENT_IP",
    "HTTP_X_REAL_IP",
    "HTTP_X_FORWARDED",
    "HTTP_X_CLUSTER_CLIENT_IP",
    "HTTP_FORWARDED_FOR",
    "HTTP_FORWARDED",
    "HTTP_CF_CONNECTING_IP",  # Cloudflare
    "HTTP_TRUE_CLIENT_IP",  # Cloudflare Enterprise / Akamai
    "HTTP_FASTLY_CLIENT_IP",  # Fastly / Firebase
    "HTTP_X_APPENGINE_USER_IP",  # Google App Engine
    "X-CLIENT-IP",  # Azure
    "X-REAL-IP",  # NGINX
    "X-CLUSTER-CLIENT-IP",  # Rackspace
    "X_FORWARDED",
    "FORWARDED_FOR",
    "CF-CONNECTING-IP",
    "TRUE-CLIENT-IP",
    "FASTLY-CLIENT-IP",
    "FORWARDED",
    "CLIENT-IP",
    "REMOTE_ADDR",
)
