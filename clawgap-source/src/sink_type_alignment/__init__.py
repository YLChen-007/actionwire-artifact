"""HC-conditioned, cross-project sink-type alignment."""

from .contracts import SinkTypeAlignmentError
from .pipeline import run_sink_type_alignment

__all__ = ["SinkTypeAlignmentError", "run_sink_type_alignment"]
