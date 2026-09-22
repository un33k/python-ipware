"""Default header precedence for the modern engine.

Superset of the v3 list, adding widely-deployed CDN/edge headers. Headers are
scanned in order; the first one that yields a globally routable IP wins, with
private and then loopback addresses as fallbacks.

Ordering rule: existing entries never move. New headers are added only in the
block just above ``REMOTE_ADDR``, so a new header can outrank the raw socket
address but never a header that already resolved a request in an earlier
release.

Every default here can be forged by a client that reaches the app directly.
If all traffic arrives through one known edge, pass an explicit
``precedence`` naming only that edge's header.
"""

DEFAULT_PRECEDENCE: tuple[str, ...] = (
    "X_FORWARDED_FOR",
    "HTTP_X_FORWARDED_FOR",
    "HTTP_CLIENT_IP",
    "HTTP_X_REAL_IP",
    "HTTP_X_FORWARDED",
    "HTTP_X_CLUSTER_CLIENT_IP",
    "HTTP_FORWARDED_FOR",  # de facto variant; not defined by RFC 7239
    "HTTP_FORWARDED",  # RFC 7239 (for=...;proto=...), parsed per element
    "HTTP_CF_CONNECTING_IP",  # Cloudflare
    "HTTP_TRUE_CLIENT_IP",  # Cloudflare Enterprise / Akamai
    "HTTP_FASTLY_CLIENT_IP",  # Fastly / Firebase
    "HTTP_FLY_CLIENT_IP",  # Fly.io
    "HTTP_X_APPENGINE_USER_IP",  # Google App Engine
    "X-CLIENT-IP",  # Azure
    "X-REAL-IP",  # NGINX
    "X-CLUSTER-CLIENT-IP",  # Rackspace
    "X_FORWARDED",
    "FORWARDED_FOR",
    "CF-CONNECTING-IP",
    "TRUE-CLIENT-IP",
    "FASTLY-CLIENT-IP",
    "FLY-CLIENT-IP",
    "FORWARDED",
    "CLIENT-IP",
    # --- added after 4.0.0: below every earlier entry, above REMOTE_ADDR ---
    "HTTP_X_CLIENT_IP",  # Azure X-Client-IP in Django/WSGI form
    "X-APPENGINE-USER-IP",  # Google App Engine, raw header form
    "HTTP_X_AZURE_CLIENTIP",  # Azure Front Door
    "X-AZURE-CLIENTIP",
    "HTTP_DO_CONNECTING_IP",  # DigitalOcean App Platform
    "DO-CONNECTING-IP",
    "HTTP_X_ENVOY_EXTERNAL_ADDRESS",  # Envoy / Istio
    "X-ENVOY-EXTERNAL-ADDRESS",
    "REMOTE_ADDR",  # direct connection; always last
)
