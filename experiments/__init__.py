from pathlib import Path
import sys
parent_directory = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(parent_directory))