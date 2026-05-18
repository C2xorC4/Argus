"""Allow `python -m tools.shellcode_gen` invocation."""
import sys
from .cli import main

sys.exit(main())
