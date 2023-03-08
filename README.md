# Python IPware (A Python Package)

**A python package for server applications to retrieve client's IP address**

[![status-image]][status-link]
[![version-image]][version-link]
[![coverage-image]][coverage-link]

# Overview

**Best attempt** to get client's IP address while keeping it **DRY**.

# Notice

There is no perfect `out-of-the-box` solution against fake IP addresses, aka `IP Address Spoofing`.
You are encouraged to read the ([Advanced users](README.md#advanced-users)) section of this page and
use `proxy_list` and/or `proxy_count` features to match your needs, especially `if` you are
planning to include `ipware` in any authentication, security or `anti-fraud` related architecture.

This is an open source project, with the source code visible to all. Therefore, it may be exploited through unimplemented, or improperly implemented features.

Please use ipware `ONLY` as a complement to your `firewall` security measures!

# How to install

    1. easy_install python-ipware
    2. pip install python-ipware
    3. git clone http:#github.com/un33k/python-ipware
        a. cd python-ipware
        b. run python setup.py install
    4. wget https:#github.com/un33k/python-ipware/zipball/master
        a. unzip the downloaded file
        b. cd into python-ipware-* directory
        c. run python setup.py install

# How to use

```python
# In a view or a middleware where the `request` object is available
import ipware
ipware = Ipware() # default values
meta = request.META # Django (meta = request.META), Flask (meta = request.environ), etc
ip, trusted_route = ipware.get_client_ip(meta)
if ip: # IPv4Address() or IPv6Address() object
    # ip object has the following properties
    # ip.is_global (is globally routable)
    # ip.is_private (is private ip address)
    # is_loopback (is loopback address)
# trusted_route tells if request came through our proxies (count / trusted)

# do something with the ip address (e.g. pass it down through the request)
# note: ip address doesn't change often, so better cache it for performance,
# try to have distinct session ID for public and anonymous users to cache the ip address

```

# Advanced users:

|        Params ⇩ | ⇩ Description                                                                                                                                                                                                                                                                                                                                                     |
| --------------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `proxy_count` ⇨ | : Total number of expected proxies (pattern: `client, proxy1, ..., proxy2`)<br>: if `proxy_count = 0` then `client`<br>: if `proxy_count = 1` then `client, proxy1`<br>: if `proxy_count = 2` then `client, proxy1, proxy2` <br>: if `proxy_count = 3` then `client, proxy1, proxy2 proxy3`                                                                       |
|  `proxy_list` ⇨ | : List of trusted proxies (pattern: `client, proxy1, ..., proxy2`)<br>: if `proxy_list = ['10.1.']` then `client, 10.1.1.1` OR `client, proxy1, 10.1.1.1`<br>: if `proxy_list = ['10.1', '10.2.']` then `client, 10.1.1.1` OR `client, proxy1, 10.2.2.2`<br>: if `proxy_list = ['10.1', '10.2.']` then `client, 10.1.1.1 10.2.2.2` OR `client, 10.1.1.1 10.2.2.2` |
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
  "X_FORWARDED_FOR", # Load balancers or proxies such as AWS ELB (default client is `leftmost` [`<client>, <proxy1>, <proxy2>`])
  "HTTP_X_FORWARDED_FOR", # Similar to X_FORWARDED_TO
  "HTTP_CLIENT_IP", # Standard headers used by providers such as Amazon EC2, Heroku etc.
  "HTTP_X_REAL_IP",
  "HTTP_X_FORWARDED",
  "HTTP_X_CLUSTER_CLIENT_IP",
  "HTTP_FORWARDED_FOR",
  "HTTP_FORWARDED",
  "HTTP_VIA",
  "X-REAL-IP", # NGINX
  "X-CLUSTER-CLIENT-IP", # Rackspace Cloud Load Balancers
  "X_FORWARDED",
  "FORWARDED_FOR",
  "CF-CONNECTING-IP", # CloudFlare
  "TRUE-CLIENT-IP", # CloudFlare Enterprise,
  "FASTLY-CLIENT-IP", # Firebase, Fastly
  "FORWARDED",
)


```

You can customize the order by providing your own list during initialization when calling `IpWare()`.

```python
# specific meta key
ipware = IpWare(precedence=("X_FORWARDED_FOR"))

# multiple meta keys
ipware = IpWare(precedence=("X_FORWARDED_FOR", "HTTP_X_FORWARDED_FOR"))

# usage is just to pass in the http request headers

# Django (request.META)
ip, proxy_verified = ipware.get_client_ip(meta=request.META)

# Flask (request.environ)
ip, proxy_verified = ipware.get_client_ip(meta=request.environ)

# ... etc.

```

### Trusted Proxies

If your node server is behind one or more known proxy server(s), you can filter out unwanted requests
by providing a `trusted proxy list`, or a known proxy `count`.

You can customize the proxy IP prefixes by providing your own list during initialization when calling `IpWare(proxy_list)`.
You can pass your custom list on every call, when calling the proxy-aware api to fetch the ip.

```python
# In the above scenario, use your load balancer IP address as a way to filter out unwanted requests.
ipware = IpWare(proxy_list=["198.84.193.157"])


# If you have multiple proxies, simply add them to the list
ipware = IpWare(proxy_list=["198.84.193.157", "198.84.193.158"])

# For proxy servers with fixed sub-domain and dynamic IP, use the following pattern.
ipware = IpWare(proxy_list=["177.139.", "177.140"])

# usage: non-strict mode (X-Forwarded-For: <fake>, <client>, <proxy1>, <proxy2>)
# The request went through our <proxy1> and <proxy2>, then our server
# We choose the <client> ip address to the left our <proxy1> and ignore other ips
ip, trusted_route = self.ipware.get_client_ip(meta=request.META)


# usage: strict mode (X-Forwarded-For: <client>, <proxy1>, <proxy2>)
# The request went through our <proxy1> and <proxy2>, then our server
# Total ip address are total trusted proxies + client ip
# We don't allow far-end proxies, or fake addresses (exact or None)
ip, trusted_route = self.ipware.get_client_ip(meta=request.META, strict=True)
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
import ipware

# enforce proxy count
ipware = IpWare(proxy_count=1)

# enforce proxy count and trusted proxies
ipware = IpWare(proxy_count=1, proxy_list=["198.84.193.157"])


# usage: non-strict mode (X-Forwarded-For: <fake>, <client>, <proxy1>, <proxy2>)
# total number of ip addresses are greater than the total count
ip, trusted_route = self.ipware.get_client_ip(meta=request.META)


# usage: strict mode (X-Forwarded-For: <client>, <proxy1>, <proxy2>)
# total number of ip addresses are exactly equal to client ip + proxy_count
ip, trusted_route = self.ipware.get_client_ip(meta=request.META, strict=True)
```

In the following `example`, your public load balancer (LB) can be seen as the `only` proxy.

```
`Real` Client <public> <-> <public> LB (Server) <private> <---> <private> Node Server
                                                            ^
                                                            |
                                `Fake` Client  <private> ---+
```

### Public IP Address ONLY (routable on the internet)

```python
# We make best attempt to return the first public IP address based on header precedence
# Then we fall back on private, followed by loopback
import ipware

# no proxy enforce in this example
ipware = IpWare()

ip, _ = self.ipware.get_client_ip(meta=request.META)

if ip.is_global:
    print('Public IP')
else if ip.is_private:
    print('Private IP')
else if ip.loopback:
    print('Loopback IP')
```

### Originating Request

Please note that the [de-facto](https:#developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For) standard
for the originating client IP address is the `leftmost`as per`client, proxy1, proxy2`, and the `rightmost` proxy is the most
trusted proxy.

However, in rare cases your network has a `custom` configuration where the `rightmost` IP address is that of the originating client. If that is the case, then indicate it when creating `IpWare(leftmost=False)`.

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
