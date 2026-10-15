import logging

from .version import PYSATOCHIP_VERSION

__version__ = PYSATOCHIP_VERSION

# Libraries must not install handlers or impose levels on the application that
# imports them. A NullHandler keeps the "no handler configured" case silent
# instead of letting records fall through to logging.lastResort (stderr).
logging.getLogger(__name__).addHandler(logging.NullHandler())


def set_log_level(level):
    """Set the level of every pysatochip logger at once.

    All modules log to `pysatochip.<module>` and none of them set their own
    level, so setting it here cascades to all of them. This is the supported
    way for an application to turn pysatochip logging up or down; it is also
    what the `loglevel` constructor arguments call into.
    """
    logging.getLogger(__name__).setLevel(level)
