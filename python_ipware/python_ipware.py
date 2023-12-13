import ipaddress
import logging

from typing import Any, Dict, List, Optional, Tuple, Union

IpAddressType = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
OptionalIpAddressType = Optional[IpAddressType]


class IpWareMeta:
    """
    A class that handles meta data frm an HTTP request.
    """

    def __init__(
        self,
        precedence: Optional[Tuple[str, ...]] = None,
        leftmost: bool = True,
    ) -> None:
        self.precedence = precedence or (
            "X_FORWARDED_FOR",  # Load balancers or proxies such as AWS ELB (default client is `left-most` [`<client>, <proxy1>, <proxy2>`])
            "HTTP_X_FORWARDED_FOR",  # Similar to X_FORWARDED_TO
            "HTTP_CLIENT_IP",  # Standard headers used by providers such as Amazon EC2, Heroku etc.
            "HTTP_X_REAL_IP",  # Standard headers used by providers such as Amazon EC2, Heroku etc.
            "HTTP_X_FORWARDED",  # Squid and others
            "HTTP_X_CLUSTER_CLIENT_IP",  # Rackspace LB and Riverbed Stingray
            "HTTP_FORWARDED_FOR",  # RFC 7239
            "HTTP_FORWARDED",  # RFC 7239
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
        self.leftmost = leftmost


class IpWareIpAddress:
    """
    A class that handles IP address data from an HTTP request.
    """

    def extract_ipv4_only(self, ip_address: str) -> str:
        """
        Given an IPv4 address or address:port, it extracts the IP address
        @param ip_str: IP address or address:port
        @return: IP address
        """

        if ip_address:
            # handle ipv4 addresses with port
            if ":" in ip_address:
                ip_address = ip_address.split(":")[0]
                return ip_address.strip()

            return ip_address.strip()

        return ""

    def extract_ipv6_only(self, ip_address: str) -> str:
        """
        Given an IPv6 address or address:port, it extracts the IP address
        @param ip_str: IP address or address:port
        @return: IP address
        """

        if ip_address:
            # handle ipv6 addresses with port
            if "]:" in ip_address:
                ip_address = ip_address.split("]:")[0]
                ip_address = ip_address.replace("[", "")
                return ip_address.strip()

            return ip_address.strip()

        return ""

    def get_ip_object(
        self,
        ip_str: str,
    ) -> OptionalIpAddressType:
        """
        Given an IP address or address:port, it parses the IP address
        @param ip_str: IP address or address:port
        @return: IP address of type IPv4Address or IPv6Address
        """

        ip: OptionalIpAddressType = None
        if ip_str:
            try:
                # try to parse as IPv6 address with optional port
                ipv6 = self.extract_ipv6_only(ip_str)
                ip = ipaddress.IPv6Address(ipv6)
                ip = ip.ipv4_mapped or ip
            except ipaddress.AddressValueError:
                try:
                    # try to parse as IPv4 address with optional port
                    ipv4 = self.extract_ipv4_only(ip_str)
                    ip = ipaddress.IPv4Address(ipv4)
                except ipaddress.AddressValueError:
                    # not a valid IP address, return None
                    logging.info("Invalid ip address. {0}".format(ip_str))
                    ip = None
        return ip

    def get_ips_from_string(
        self,
        ip_str: str,
    ) -> Optional[List[IpAddressType]]:
        """
        Given a comma separated list of IP addresses or address:port, it parses the IP addresses
        @param ip_str: comma separated list of IP addresses or address:port
        @return: list of IP addresses of type IPv4Address or IPv6Address
        """
        ip_list: List[IpAddressType] = []

        for ip_address in ip_str.split(","):
            ip = self.get_ip_object(ip_address.strip())
            if ip:
                ip_list.append(ip)
            else:
                # we have at least one invalid IP address, return empty list, instead
                return None

        if not self.leftmost:
            ip_list.reverse()

        return ip_list


class IpWareProxy:
    """
    A class that handles proxy data from an HTTP request.
    """

    def __init__(
        self,
        proxy_count: int = 0,
        proxy_list: Optional[List[str]] = None,
    ) -> None:
        if proxy_count is None or proxy_count < 0:
            raise ValueError("proxy_count must be a positive integer")

        self.proxy_count = proxy_count
        self.proxy_list = self._is_valid_proxy_trusted_list(proxy_list or [])

    def _is_valid_proxy_trusted_list(self, proxy_list: Any) -> List[str]:
        """
        Checks if the proxy list is a valid list of strings
        @return: proxy list or raises an exception
        """

        if not isinstance(proxy_list, list):
            raise ValueError("Parameter must be a list")
        if not all(isinstance(x, str) for x in proxy_list):
            raise ValueError("All elements in list must be strings")

        return proxy_list

    def is_proxy_count_valid(
        self, ip_list: List[IpAddressType], strict: bool = False
    ) -> bool:
        """
        Checks if the proxy count is valid
        @param ip_list: list of ip addresses
        @param strict: if True, we must have exactly proxy_count proxies
        @return: True if the proxy count is valid, False otherwise
        """
        if self.proxy_count < 1:
            return True

        ip_count: int = len(ip_list)
        if ip_count < 1:
            return False

        if strict:
            # our first proxy takes the last ip address and treats it as client ip
            return self.proxy_count == ip_count - 1

        # the client could have gone through their own proxy and included extra ips
        # client could be sending in the header: X-Forwarded-For: <fake_ip>, <client_ip>
        return ip_count - 1 > self.proxy_count

    def is_proxy_trusted_list_valid(
        self,
        ip_list: List[IpAddressType],
        strict: bool = False,
    ) -> bool:
        """
        Checks if the proxy list is valid (all proxies are in the proxy_list)
        @param ip_list: list of ip addresses
        @param strict: if True, we must have exactly proxy_count proxies
        @return: client's best match ip address or False
        """
        if not self.proxy_list:
            return True

        ip_count = len(ip_list)
        proxy_list_count = len(self.proxy_list)

        # in strict mode, total ip count must be 1 more than proxy count
        if strict and ip_count - 1 != proxy_list_count:
            return False

        # total ip count (client + proxies) must be more than proxy count
        if ip_count - 1 < proxy_list_count:
            return False

        # start from the end, slice the incoming ip list to the same length as the trusted proxy list
        ip_list_slice = ip_list[-proxy_list_count:]
        for index, value in enumerate(ip_list_slice):
            if not str(value).startswith(self.proxy_list[index]):
                return False

        # now all we need is to return the first ip in the list that is not in the trusted proxy list
        # best_client_ip_index = proxy_list_count + 1
        # best_client_ip = ip_list[-best_client_ip_index]

        return True


class IpWare(IpWareMeta, IpWareProxy, IpWareIpAddress):
    """
    A class that makes best effort to determine the client's IP address.
    """

    def __init__(
        self,
        precedence: Optional[Tuple[str, ...]] = None,
        leftmost: bool = True,
        proxy_count: int = 0,
        proxy_list: Optional[List[str]] = None,
    ) -> None:
        IpWareMeta.__init__(self, precedence, leftmost)
        IpWareProxy.__init__(self, proxy_count or 0, proxy_list or [])

    def get_meta_value(self, meta: Dict[str, str], key: str) -> str:
        """
        Given a key, it returns a cleaned up version of the value
        @param key: the key to lookup
        @return: the value of the key or empty string
        """
        meta = meta or {}
        return meta.get(key, meta.get(key.replace("_", "-"), "")).strip()

    def get_meta_values(self, meta: Dict[str, str]) -> List[str]:
        """
        Given a list of keys, it returns a list of cleaned up values
        @return: a list of values
        """
        return [self.get_meta_value(meta, key) for key in self.precedence]

    def get_client_ip(
        self,
        meta: Dict[str, str],
        strict: bool = False,
    ) -> Tuple[OptionalIpAddressType, bool]:
        """
        Returns the client's IP address.
        """

        loopback_list: List[IpAddressType] = []
        private_list: List[OptionalIpAddressType] = []

        for ip_str in self.get_meta_values(meta):
            if not ip_str:
                continue

            ip_list = self.get_ips_from_string(ip_str)
            if not ip_list:
                continue

            proxy_count_validated = self.is_proxy_count_valid(ip_list, strict)
            if not proxy_count_validated:
                continue

            proxy_list_validated = self.is_proxy_trusted_list_valid(ip_list, strict)
            if not proxy_list_validated:
                continue

            client_ip, trusted_route = self.get_best_ip(
                ip_list, proxy_count_validated, proxy_list_validated
            )

            # we found a global ip, return it
            if client_ip is not None and client_ip.is_global:
                return client_ip, trusted_route

            # we found a private ip, save it
            if client_ip is not None and client_ip.is_loopback:
                loopback_list.append(client_ip)
            else:
                # if not global (public) or loopback (local), we treat it asd private
                private_list.append(client_ip)

        # we have not been able to locate a global ip
        # it could be the server is running on the intranet
        # we will return the first private ip we found
        if private_list:
            return private_list[0], False

        # we have not been able to locate a global ip, nor a private ip
        # it could be the server is running on a loopback address serving local requests
        if loopback_list:
            return loopback_list[0], False

        # we were unable to find any ip address
        return None, False

    def get_best_ip(
        self,
        ip_list: List[IpAddressType],
        proxy_count_validated: bool = True,
        proxy_list_validated: bool = True,
    ) -> Tuple[OptionalIpAddressType, bool]:
        """
        Returns the best possible ip for the client.
        """

        if not ip_list:
            logging.warning("Invalid ip list provided.")
            return None, False

        # the incoming ips match our trusted proxy list
        if len(self.proxy_list) > 0 and proxy_list_validated:
            best_client_ip_index = len(self.proxy_list) + 1
            best_client_ip = ip_list[-best_client_ip_index]
            return best_client_ip, True

        # the incoming ips match our proxy count
        if self.proxy_count > 0 and proxy_count_validated:
            best_client_ip_index = self.proxy_count + 1
            best_client_ip = ip_list[-best_client_ip_index]
            return best_client_ip, True

        # we don't track proxy related info, so we just return the first ip
        return ip_list[0], False
