# Python IPware (A Python Package)

**A python package for server applications to retrieve client's IP address**

[![status-image]][status-link]
[![version-image]][version-link]
[![coverage-image]][coverage-link]

# Overview

**Best attempt** to get client's IP address while keeping it **DRY**.

# Notice

### Addressing IP Address Spoofing

There is no perfect `out-of-the-box` solution to counteract fake IP addresses, or IP Address Spoofing. We strongly recommend reading the [Advanced Users](README.md#advanced-users) section. Utilize the `proxy_list` and `proxy_count` features to adapt the functionality to your specific requirements, especially if you plan to incorporate `python-ipware` into authentication, security, or anti-fraud systems.

### Open Source Considerations

Keep in mind that `python-ipware` is an open-source project, meaning its source code is accessible to everyone. While this openness promotes community engagement and scrutiny, it also exposes the code to potential exploiters who might take advantage of unimplemented or improperly implemented features.

### Complementary Security Measure

Use `python-ipware` **only** as an additional layer to bolster your security, not as a primary defense mechanism. Always pair it with robust firewall security protocols to ensure comprehensive protection against a variety of security threats, including IP spoofing.

# How to install

```
pip install python-ipware
```
-- or --
```
pip3 install python-ipware
```

# How to use

### Using python-ipware to Retrieve Client IP in Django or Flask

Here's a basic example of how to use `python-ipware` in a view or middleware where the `request` object is available. This can be applied in Django, Flask, or other similar frameworks.

```python
from python_ipware import IpWare

# Instantiate IpWare with default values
ipw = IpWare()

# Get the META data from the request object
meta = request.META  # Django
# meta = request.environ # Flask

# Get the client IP and the trusted route flag
ip, trusted_route = ipw.get_client_ip(meta)

if ip:
    # The 'ip' is an object of type IPv4Address() or IPv6Address() with properties like:
    # - ip.is_global: True if the IP is globally routable
    # - ip.is_private: True if the IP is a private address
    # - ip.is_loopback: True if the IP is a loopback address
    # - ip.is_multicast: True if the IP is a multicast address
    # - ip.is_unspecified: True if the IP is an unspecified address
    # - ip.is_reserved: True if the IP is a reserved address

if trusted_route:
    # Indicates if the request came through our trusted proxies

# You can now use the IP address as needed, for example, attaching it to the request object.
# Consider caching the IP address for performance, as it doesn't change often.
# It's also advisable to have distinct session IDs for public and anonymous users to cache the IP address effectively.
```

# Advanced users:

|        Params ⇩ | ⇩ Description                                                                                                                                                                                                                                                                                                                                                     |
| --------------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `proxy_count` ⇨ | : Total number of expected proxies (pattern: `client, proxy1, ..., proxy2`)<br>: if `proxy_count = 0` then `client`<br>: if `proxy_count = 1` then `client, proxy1`<br>: if `proxy_count = 2` then `client, proxy1, proxy2` <br>: if `proxy_count = 3` then `client, proxy1, proxy2 proxy3`                                                                       |
|  `proxy_list` ⇨ | : List of trusted proxies (ip header pattern: `client, proxy1, ,..., proxyN`)<br>: if `proxy_list = ['10.1.']` then `client, proxy1`<br>: if `proxy_list = ['10.1', '10.2.3']` then `client, proxy1 proxy2`<br>: if `proxy_list = ['10.1', '10.2.', '10.3.4.4']` then `client, proxy1, proxy2, proxy3` |
|    `leftmost` ⇨ | : `leftmost = True` is default for de-facto standard.<br>: `leftmost = False` for rare legacy networks that are configured with the `rightmost` pattern.<br>: It converts `client, proxy1 proxy2` to `proxy2, proxy1, client`                                                                                                                                     |

|          Output ⇩ | ⇩ Description                                                                                |
| ----------------: | :------------------------------------------------------------------------------------------- |
|            `ip` ⇨ | : Client IP address object of type IPv4Address() or IPv6Address()                            |
| `trusted_route` ⇨ | : If proxy `proxy_count` and/or `proxy_list` were provided and matched, `True`, else `False` |

### Precedence Order

The client IP address can be found in one or more request headers attributes. The lookup order is top to bottom and the default attributes are as follow.

```python
# The default meta precedence order - you can be more specific as per your configuration
# It will start looking through the request headers from top to bottom to find the best match
# It will return the first qualified global (public) ip address it finds, else
# It will return the first qualified private ip address it finds, else
# It will return the first qualified loopback up address it finds, else it returns None
# Update as per your network topology, reduce the numbers and/or reorder the list
request_headers_precedence_order = (
    "X_FORWARDED_FOR",  # Load balancers or proxies such as AWS ELB (default client is `left-most` [`<client>, <proxy1>, <proxy2>`])
    "HTTP_X_FORWARDED_FOR",  # Similar to X_FORWARDED_TO
    "HTTP_CLIENT_IP",  # Standard headers used by providers such as Amazon EC2, Heroku etc.
    "HTTP_X_REAL_IP",  # Standard headers used by providers such as Amazon EC2, Heroku etc.
    "HTTP_X_FORWARDED",  # Squid and others
    "HTTP_X_CLUSTER_CLIENT_IP",  # Rackspace LB and Riverbed Stingray
    "HTTP_FORWARDED_FOR",  # RFC 7239
    "HTTP_FORWARDED",  # RFC 7239
    "HTTP_CF_CONNECTING_IP",  # CloudFlare
    "X-CLIENT-IP",  # Microsoft Azure
    "X-REAL-IP",  # NGINX
    "X-CLUSTER-CLIENT-IP",  # Rackspace Cloud Load Balancers
    "X_FORWARDED",  # Squid
    "FORWARDED_FOR",  # RFC 7239
    "CF-CONNECTING-IP",  # CloudFlare
    "TRUE-CLIENT-IP",  # CloudFlare Enterprise,
    "FASTLY-CLIENT-IP",  # Firebase, Fastly
    "FORWARDED",  # RFC 7239
    "CLIENT-IP",  # Akamai and Cloudflare: True-Client-IP and Fastly: Fastly-Client-IP
    "REMOTE_ADDR",  # Default
)
```

You can customize the order by providing your own list during initialization when calling `IpWare()`.

```python
# specific meta key
ipw = IpWare(precedence=("X_FORWARDED_FOR"))

# multiple meta keys
ipw = IpWare(precedence=("X_FORWARDED_FOR", "HTTP_X_FORWARDED_FOR"))

# Django (request.META)
ip, proxy_verified = ipw.get_client_ip(meta=request.META)

# Flask (request.environ)
ip, proxy_verified = ipw.get_client_ip(meta=request.environ)

# ... etc.

```

### Trusted Proxies

If your node server is behind one or more known proxy server(s), you can filter out unwanted requests
by providing a `trusted proxy list`, or a known proxy `count`.

You can customize the proxy IP prefixes by providing your own list during initialization when calling `IpWare(proxy_list)`.
You can pass your custom list on every call, when calling the proxy-aware api to fetch the ip.

```python
# In the above scenario, use your load balancer IP address as a way to filter out unwanted requests.
ipw = IpWare(proxy_list=["198.84.193.157"])


# If you have multiple proxies, simply add them to the list
ipw = IpWare(proxy_list=["198.84.193.157", "198.84.193.158"])

# For proxy servers with fixed sub-domain and dynamic IP, use the following pattern.
ipw = IpWare(proxy_list=["177.139.", "177.140"])

# usage: non-strict mode (X-Forwarded-For: <fake>, <client>, <proxy1>, <proxy2>)
# The request went through our <proxy1> and <proxy2>, then our server
# We choose the <client> ip address to the left our <proxy1> and ignore other ips
ip, trusted_route = ipw.get_client_ip(meta=request.META)


# usage: strict mode (X-Forwarded-For: <client>, <proxy1>, <proxy2>)
# The request went through our <proxy1> and <proxy2>, then our server
# Total ip address are total trusted proxies + client ip
# We don't allow far-end proxies, or fake addresses (exact or None)
ip, trusted_route = ipw.get_client_ip(meta=request.META, strict=True)
```

In the following `example`, your public load balancer (LB) can be seen as a `trusted` proxy.

```
`Real` Client <public> <-> <public> LB (Server) <private> <-----> <private> Django Server
                                                             ^
                                                             |
`Fake` Client <private> <-> <private> LB (Server) <private> -+
```

### Proxy Count

If your python server is behind a `known` number of proxies, but you deploy on multiple providers and don't want to track proxy IPs, you still can filter out unwanted requests by providing proxy `count`.

You can customize the proxy count by providing your `proxy_count` during initialization when calling `IpWare(proxy_count=2)`.

```python
# In the above scenario, the total number of proxies can be used as a way to filter out unwanted requests.
from python_ipware import IpWare

# enforce proxy count
ipw = IpWare(proxy_count=1)

# enforce proxy count and trusted proxies
ipw = IpWare(proxy_count=1, proxy_list=["198.84.193.157"])


# usage: non-strict mode (X-Forwarded-For: <fake>, <client>, <proxy1>, <proxy2>)
# total number of ip addresses are greater than the total count
ip, trusted_route = ipw.get_client_ip(meta=request.META)


# usage: strict mode (X-Forwarded-For: <client>, <proxy1>, <proxy2>)
# total number of ip addresses are exactly equal to client ip + proxy_count
ip, trusted_route = ipw.get_client_ip(meta=request.META, strict=True)
```

In the following `example`, your public load balancer (LB) can be seen as the `only` proxy.

```
`Real` Client <public> <-> <public> LB (Server) <private> <---> <private> Node Server
                                                            ^
                                                            |
                                `Fake` Client  <private> ---+
```

### Support for Public IP Address (routable on the internet), Private and Loopback

```python
# We make best attempt to return the first public IP address based on header precedence
# Then we fall back on private, followed by loopback
from python_ipware import IpWare

# no proxy enforce in this example
ipw = IpWare()

ip, _ = ipw.get_client_ip(meta=request.META)

if ip.is_global:
    print('Public IP')
else if ip.is_private:
    print('Private IP')
else if ip.is_loopback:
    print('Loopback IP')
else if ip.is_multicast:
    print('Multicast IP')
else if ip.is_unspecified:
    print('Unspecified IP')
else if ip.is_reserved:
    print('Reserved IP')
```


### IP Address Handling

#### Support for IPv4, IPv6, and IP:Port Patterns

`python-ipware` is designed to handle various IP address formats efficiently:

- **Ports Stripping:** Automatically removes ports from IP addresses, ensuring only the IP is processed.
- **IPv6 Unwrapping:** Extracts and processes IPv4 addresses wrapped in IPv6 containers.

#### Identifying the Originating IP Address

The [de-facto standard](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For) for identifying the originating client IP address is to use the `leftmost` IP in the `X-Forwarded-For` header, following the pattern `client, proxy1, proxy2`. Here, the `rightmost` IP is considered the most trusted proxy.

##### Custom Network Configurations

In some rare scenarios, networks might be configured such that the `rightmost` IP address represents the originating client. In such cases, instantiate `IpWare` with the `leftmost=False` parameter:


# Running the tests

To run the tests against the current environment:

    ./test.sh

# License

Released under a ([MIT](https:#raw.githubusercontent.com/un33k/python-ipware/main/LICENSE)) license.

# Version

X.Y.Z Version

    `MAJOR` version -- making incompatible API changes
    `MINOR` version -- adding functionality in a backwards-compatible manner
    `PATCH` version -- making backwards-compatible bug fixes

[status-image]: https://github.com/un33k/python-ipware/actions/workflows/ci.yml/badge.svg
[status-link]: https://github.com/un33k/python-ipware/actions/workflows/ci.yml
[version-image]: https://img.shields.io/pypi/v/python-ipware.svg
[version-link]: https://pypi.python.org/pypi/python-ipware?branch=main
[coverage-image]: https://coveralls.io/repos/github/un33k/python-ipware/badge.svg?branch=main
[coverage-link]: https://coveralls.io/github/un33k/python-ipware?branch=main
[download-image]: https://img.shields.io/pypi/dm/python-ipware.svg
[download-link]: https://pypi.python.org/pypi/python-ipware

# Sponsors

[Neekware Inc.](http://neekware.com)

# Need Support?

[Neekware Inc.](http://neekware.com) (reach out at info@neekware.com)
