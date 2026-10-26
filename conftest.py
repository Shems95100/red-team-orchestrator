import sys
from pathlib import Path

# Permet à pytest de trouver les paquets core/ et modules/ depuis la racine.
sys.path.insert(0, str(Path(__file__).parent))
