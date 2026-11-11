"""
Tsukiko Hardware Verification & Compatibility Diagnostic Script
Convenience entry point for running diagnostics from the source repository.
Delegates to app.core.resource_manager.diagnostic.
"""

import sys
from pathlib import Path

# Add project root to path if running directly from scripts/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.resource_manager.diagnostic import run_hardware_diagnostic


def main() -> int:
    return run_hardware_diagnostic()


if __name__ == "__main__":
    sys.exit(main())
