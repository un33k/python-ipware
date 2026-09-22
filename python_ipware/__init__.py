from .__version__ import __version__
from .legacy import LegacyIpWare
from .modern import ModernIpWare
from .router import IpWare

__all__ = ["IpWare", "LegacyIpWare", "ModernIpWare", "__version__"]
