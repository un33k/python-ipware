import ipaddress
import logging

from typing import Dict, List, Optional, Tuple, Union

IpAddressType = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
OptionalIpAddressType = Optional[IpAddressType]

logger = logging.getLogger(__name__)


class IpWareMeta:
    """
    A class to manage metadata extracted from HTTP request headers, primarily for identifying
    the client's IP address behind load balancers and proxies.
    """

    def __init__(
        self, precedence: Optional[Tuple[str, ...]] = None, leftmost: bool = True
    ) -> None:
        """
        Initializes the metadata handler with a precedence list of HTTP headers and the position of the client IP.

        :param precedence: A tuple of header names that define the order to check for a valid IP.
                           If not provided, a default list of commonly used headers is applied.
        :param leftmost: A boolean that indicates whether to use the left-most IP in the header
                         when multiple IPs are listed (typically the case with proxies).
        """
        # Default precedence list of headers if none is provided
        if precedence is None:
            precedence = (
                "X_FORWARDED_FOR",  # Common header for proxies, load balancers, like AWS ELB. Default to the left-most IP.
                "HTTP_X_FORWARDED_FOR",  # Alternative header similar to `X_FORWARDED_FOR`.
                "HTTP_CLIENT_IP",  # Header used by some providers like Amazon EC2, Heroku.
                "HTTP_X_REAL_IP",  # Header used by some providers like Amazon EC2, Heroku.
                "HTTP_X_FORWARDED",  # Used by Squid and similar software.
                "HTTP_X_CLUSTER_CLIENT_IP",  # Used by Rackspace LB, Riverbed Stingray.
                "HTTP_FORWARDED_FOR",  # Standard header defined by RFC 7239.
                "HTTP_FORWARDED",  # Standard header defined by RFC 7239.
                "HTTP_CF_CONNECTING_IP",  # Used by CloudFlare.
                "X-CLIENT-IP",  # Used by Microsoft Azure.
                "X-REAL-IP",  # Commonly used by NGINX.
                "X-CLUSTER-CLIENT-IP",  # Used by Rackspace Cloud Load Balancers.
                "X_FORWARDED",  # Used by Squid.
                "FORWARDED_FOR",  # Standard header defined by RFC 7239.
                "CF-CONNECTING-IP",  # Used by CloudFlare.
                "TRUE-CLIENT-IP",  # Header for CloudFlare Enterprise.
                "FASTLY-CLIENT-IP",  # Used by Fastly, Firebase.
                "FORWARDED",  # Standard header defined by RFC 7239.
                "CLIENT-IP",  # Used by Akamai, Cloudflare's True-Client-IP, and Fastly's Fastly-Client-IP.
                "REMOTE_ADDR",  # The default IP address header (direct connection).
            )

        self.precedence = precedence
        self.leftmost = leftmost


class IpWareIpAddress:
    """
    A class for handling and parsing IP address data from HTTP requests.
    """

    def extract_ipv4(self, ip_address: str) -> str:
        """
        Extracts the IPv4 address from a given string that may include a port number.

        Args:
            ip_address (str): An IPv4 address possibly including a port (e.g., "192.168.1.1:8080").

        Returns:
            str: The IPv4 address without the port. Returns an empty string if input is None.
        """
        if ip_address:
            return ip_address.split(":")[0].strip()
        return ""

    def extract_ipv6(self, ip_address: str) -> str:
        """
        Extracts the IPv6 address from a given string that may include a port number.

        Args:
            ip_address (str): An IPv6 address possibly including a port (e.g., "[2001:db8::1]:8080").

        Returns:
            str: The IPv6 address without brackets or port. Returns an empty string if input is None.
        """
        if ip_address and "]:" in ip_address:
            return ip_address.split("]:")[0].replace("[", "").strip()
        return ip_address.strip() if ip_address else ""

    def parse_ip_address(self, ip_str: str):
        """
        Parses the given IP address string to an IPv4Address or IPv6Address object.

        Args:
            ip_str (str): An IP address possibly including a port.

        Returns:
            ipaddress.IPv4Address|ipaddress.IPv6Address|None: The parsed IP object or None if the address is invalid.
        """
        try:
            # First, try to parse as IPv6.
            ipv6 = self.extract_ipv6(ip_str)
            ip = ipaddress.IPv6Address(ipv6)
            return ip.ipv4_mapped or ip
        except ipaddress.AddressValueError:
            try:
                # If IPv6 parsing fails, try to parse as IPv4.
                ipv4 = self.extract_ipv4(ip_str)
                return ipaddress.IPv4Address(ipv4)
            except ipaddress.AddressValueError:
                # Log error if IP is invalid
                # print(f"Invalid IP address: {ip_str}")
                return None

    def get_ips_from_string(
        self,
        ip_str: str,
        strict: bool = False,
    ) -> Optional[List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]]:
        """
        Parses a comma-separated list of IP addresses, each possibly including a port.

        Args:
            ip_str (str): A comma-separated list of IP addresses or address:port entries.
            strict (bool): True to bail out on first invalid ip, False to skip invalid ip
        Returns:
            List[ipaddress.IPv4Address|ipaddress.IPv6Address]|None: A list of IP address objects or None if any IP is invalid.
        """
        ip_list = []
        for ip_address in ip_str.split(","):
            ip = self.parse_ip_address(ip_address.strip())
            if ip:
                ip_list.append(ip)
            else:
                if strict:
                    return None

        if not self.leftmost:
            ip_list.reverse()

        return ip_list


class IpWareProxy:
    """
    A class to handle proxy data from an HTTP request, including validating
    proxy counts and trusted proxy lists.
    """

    def __init__(
        self, proxy_count: Optional[int] = None, proxy_list: Optional[List[str]] = None
    ) -> None:
        """
        Initialize the IpWareProxy class with optional proxy count and proxy list.

        Args:
            proxy_count: The expected number of proxies, can be None if no specific count is enforced.
            proxy_list: A list of partial IP addresses as trusted proxies, can be None.
        """
        if proxy_count is not None and proxy_count < 0:
            raise ValueError("proxy_count must be non-negative")
        self.proxy_count = proxy_count
        self.proxy_list = self._validate_proxy_list(proxy_list or [])

    def _validate_proxy_list(self, proxy_list: List[str]) -> List[str]:
        """
        Validates that the proxy list contains only strings.

        Args:
            proxy_list: A list of proxies.

        Returns:
            The proxy list if all items are valid strings.

        Raises:
            ValueError: If the proxy list is not a list of strings.
        """
        if not all(isinstance(ip, str) for ip in proxy_list):
            raise ValueError("All elements in the proxy list must be strings.")
        return proxy_list

    def is_proxy_count_valid(self, ip_list: List[str], strict: bool = False) -> bool:
        """
        Validates the proxy count against a list of IP addresses.

        Args:
            ip_list: A list of IP addresses from the request headers.
            strict: If True, the number of proxies must exactly match the proxy_count.

        Returns:
            True if the proxy count is valid, False otherwise.
        """
        if self.proxy_count is None:
            return True  # No proxy count specified, so always valid.

        ip_count = len(ip_list)
        if strict:
            return ip_count - 1 == self.proxy_count
            # Exact match required, excluding client's own IP.

        return ip_count - 1 >= self.proxy_count
        # Allow more proxies than the count, excluding client's IP.

    def is_proxy_trusted_list_valid(
        self, ip_list: List[str], strict: bool = False
    ) -> bool:
        """
        Checks if all proxies in the incoming list are trusted based on the proxy_list.

        Args:
            ip_list: A list of IP addresses from the request headers.
            strict: If True, the number of proxies must exactly match the length of proxy_list.

        Returns:
            True if all proxies are trusted, False otherwise.
        """
        if not self.proxy_list:
            return True  # No specific proxies to trust, so always valid.

        ip_count = len(ip_list)
        proxy_list_count = len(self.proxy_list)

        if strict and ip_count - 1 != proxy_list_count:
            return False  # Strict mode: Exact count match required.

        if ip_count - 1 < proxy_list_count:
            return False  # Not enough IPs to match the trusted proxies.

        # Verify each proxy against the trusted list by comparing each corresponding element.
        return all(
            str(ip).startswith(trusted_proxy_pattern)
            for ip, trusted_proxy_pattern in zip(
                ip_list[-proxy_list_count:], self.proxy_list
            )
        )


class IpWare(IpWareMeta, IpWareProxy, IpWareIpAddress):
    """
    A class that makes a best effort to determine the client's IP address.
    """

    def __init__(
        self,
        precedence: Optional[Tuple[str, ...]] = None,
        leftmost: bool = True,
        proxy_count: Optional[int] = None,
        proxy_list: Optional[List[str]] = None,
    ) -> None:
        IpWareMeta.__init__(self, precedence, leftmost)
        IpWareProxy.__init__(self, proxy_count, proxy_list)

    def get_meta_value(self, meta: Dict[str, str], key: str) -> str:
        """
        Returns a cleaned up version of the value for a given key.
        @param key: The key to look up.
        @return: The value of the key or an empty string if the key is not found.
        """
        meta = meta or {}
        return meta.get(key, meta.get(key.replace("_", "-"), "")).strip()

    def get_meta_values(self, meta: Dict[str, str]) -> List[str]:
        """
        Returns a list of cleaned up values for the keys defined in 'precedence'.
        @return: A list of values.
        """
        meta_list: List[str] = []
        for key in self.precedence:
            value = self.get_meta_value(meta, key).strip()
            if value:
                meta_list.append(value)
        return meta_list

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
            ip_list = self.get_ips_from_string(ip_str, strict)
            if not ip_list:
                continue

            proxy_count_validated = self.is_proxy_count_valid(ip_list, strict)
            if not proxy_count_validated:
                continue

            proxy_list_validated = self.is_proxy_trusted_list_valid(ip_list, strict)
            if not proxy_list_validated:
                continue

            client_ip, trusted_route = self.get_best_ip(ip_list)
            if client_ip is not None:
                if client_ip.is_global:
                    return client_ip, trusted_route
                if client_ip.is_loopback:
                    loopback_list.append(client_ip)
                else:
                    private_list.append(client_ip)

        if private_list:
            return private_list[0], False
        if loopback_list:
            return loopback_list[0], False
        return None, False

    def get_best_ip(
        self,
        ip_list: List[IpAddressType],
    ) -> Tuple[OptionalIpAddressType, bool]:
        """
        Determines the best possible IP address for the client from a list of IP addresses.
        """
        if not ip_list:
            logger.warning("Invalid IP list provided.")
            return None, False

        if self.proxy_list and len(self.proxy_list) > 0:
            best_client_ip_index = len(self.proxy_list) + 1
            best_client_ip = ip_list[-best_client_ip_index]
            return best_client_ip, True

        if self.proxy_count is not None:
            best_client_ip_index = self.proxy_count + 1
            best_client_ip = ip_list[-best_client_ip_index]
            return best_client_ip, True

        return ip_list[0], False
