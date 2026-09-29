"""Static, source-backed model-facing handler specifications."""

from .core import SCHEMA_VERSION, SpecificationError
from .service import build_all_inventories, build_project_inventory, generate_all

__all__ = [
    "SCHEMA_VERSION",
    "SpecificationError",
    "build_all_inventories",
    "build_project_inventory",
    "generate_all",
]

