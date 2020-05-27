#from .version import SATOCHIP_BRIDGE_VERSION
#from .SatochipBridge import SatochipBridge

#from .CardConnector import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION, SATOCHIP_LIB_REVISION
from .CardConnector import CardConnector

#__version__ = SATOCHIP_BRIDGE_VERSION 
#__version__ = str(SATOCHIP_PROTOCOL_MAJOR_VERSION) + '.' + str(SATOCHIP_PROTOCOL_MINOR_VERSION) + '.' + str(SATOCHIP_LIB_REVISION)
__version__ = str(CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION) + '.' + str(CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION) + '.' + str(CardConnector.SATOCHIP_LIB_REVISION)