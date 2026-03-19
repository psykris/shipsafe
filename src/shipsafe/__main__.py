"""Allow running ShipSafe as ``python -m shipsafe``."""

import sys

from shipsafe.cli import main

sys.exit(main())
