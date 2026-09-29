"""Assemble validated per-gate semantics into one ordered call-chain record."""

from .assembler import CallChainSliceV2
from .contracts import validate_call_chain_semantic_ir

__all__ = ["CallChainSliceV2", "validate_call_chain_semantic_ir"]
