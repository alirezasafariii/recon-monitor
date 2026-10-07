#!/usr/bin/env python3
"""Source checkout entry point; implementation also survives legacy updater layouts."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from release_ci_gate import main

if __name__ == '__main__':
    main()
