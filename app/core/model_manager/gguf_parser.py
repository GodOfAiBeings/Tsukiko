"""Tsukiko Local AI Brain — Pure-Python GGUF Metadata Inspector.

Inspects GGUF v2 and v3 files in read-only binary mode without requiring
heavy external libraries or loading tensor weights into memory.
"""

from __future__ import annotations

import io
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field

GGUF_MAGIC = b"GGUF"
GGUF_DEFAULT_ALIGNMENT = 32

# GGUF Value Types
GGUF_TYPE_UINT8 = 0
GGUF_TYPE_INT8 = 1
GGUF_TYPE_UINT16 = 2
GGUF_TYPE_INT16 = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_INT32 = 5
GGUF_TYPE_FLOAT32 = 6
GGUF_TYPE_BOOL = 7
GGUF_TYPE_STRING = 8
GGUF_TYPE_ARRAY = 9
GGUF_TYPE_UINT64 = 10
GGUF_TYPE_INT64 = 11
GGUF_TYPE_FLOAT64 = 12

# Common GGUF File Type / Quantization mapping
GGUF_FILE_TYPES: Dict[int, str] = {
    0: "ALL_F32",
    1: "MOSTLY_F16",
    2: "MOSTLY_Q4_0",
    3: "MOSTLY_Q4_1",
    7: "MOSTLY_Q8_0",
    8: "MOSTLY_Q5_0",
    9: "MOSTLY_Q5_1",
    10: "MOSTLY_Q2_K",
    11: "MOSTLY_Q3_K_S",
    12: "MOSTLY_Q3_K_M",
    13: "MOSTLY_Q3_K_L",
    14: "MOSTLY_Q4_K_S",
    15: "MOSTLY_Q4_K_M",
    16: "MOSTLY_Q5_K_S",
    17: "MOSTLY_Q5_K_M",
    18: "MOSTLY_Q6_K",
    19: "MOSTLY_IQ2_XXS",
    20: "MOSTLY_IQ2_XS",
    21: "MOSTLY_Q2_K_S",
    22: "MOSTLY_IQ3_XS",
    23: "MOSTLY_IQ3_XXS",
    24: "MOSTLY_IQ1_S",
    25: "MOSTLY_IQ4_NL",
    26: "MOSTLY_IQ3_S",
    27: "MOSTLY_IQ3_M",
    28: "MOSTLY_IQ2_S",
    29: "MOSTLY_IQ2_M",
    30: "MOSTLY_IQ4_XS",
    31: "MOSTLY_IQ1_M",
    32: "MOSTLY_BF16",
}


class GGUFValidationError(ValueError):
    """Raised when a candidate model file fails GGUF structure validation."""
    pass


class GGUFMetadata(BaseModel):
    """Validated metadata extracted from a GGUF model file."""
    path: Path
    version: int
    tensor_count: int
    kv_count: int
    file_size_bytes: int
    architecture: str = "unknown"
    model_name: str = "Unknown Model"
    quantization: str = "Unknown"
    context_length: int = 4096
    block_count: int = 0
    embedding_length: int = 0
    feed_forward_length: int = 0
    head_count: int = 0
    chat_template: Optional[str] = None
    all_kv: Dict[str, Any] = Field(default_factory=dict)

    @property
    def file_size_mb(self) -> int:
        return int(self.file_size_bytes / (1024 * 1024))


def _read_string(f: io.BufferedReader) -> str:
    """Reads a length-prefixed uint64 UTF-8 string."""
    len_bytes = f.read(8)
    if len(len_bytes) < 8:
        raise GGUFValidationError("Unexpected EOF reading string length.")
    str_len = struct.unpack("<Q", len_bytes)[0]
    if str_len > 10 * 1024 * 1024:  # 10MB sanity cap
        raise GGUFValidationError(f"String length {str_len} exceeds safe limit.")
    raw_str = f.read(str_len)
    if len(raw_str) < str_len:
        raise GGUFValidationError(f"Unexpected EOF reading string data (expected {str_len} bytes).")
    return raw_str.decode("utf-8", errors="replace")


def _read_value(f: io.BufferedReader, val_type: int) -> Any:
    """Reads a single typed GGUF value from the binary stream."""
    if val_type == GGUF_TYPE_UINT8:
        b = f.read(1)
        if not b:
            raise GGUFValidationError("Unexpected EOF reading UINT8.")
        return struct.unpack("<B", b)[0]
    elif val_type == GGUF_TYPE_INT8:
        b = f.read(1)
        if not b:
            raise GGUFValidationError("Unexpected EOF reading INT8.")
        return struct.unpack("<b", b)[0]
    elif val_type == GGUF_TYPE_UINT16:
        b = f.read(2)
        if len(b) < 2:
            raise GGUFValidationError("Unexpected EOF reading UINT16.")
        return struct.unpack("<H", b)[0]
    elif val_type == GGUF_TYPE_INT16:
        b = f.read(2)
        if len(b) < 2:
            raise GGUFValidationError("Unexpected EOF reading INT16.")
        return struct.unpack("<h", b)[0]
    elif val_type == GGUF_TYPE_UINT32:
        b = f.read(4)
        if len(b) < 4:
            raise GGUFValidationError("Unexpected EOF reading UINT32.")
        return struct.unpack("<I", b)[0]
    elif val_type == GGUF_TYPE_INT32:
        b = f.read(4)
        if len(b) < 4:
            raise GGUFValidationError("Unexpected EOF reading INT32.")
        return struct.unpack("<i", b)[0]
    elif val_type == GGUF_TYPE_FLOAT32:
        b = f.read(4)
        if len(b) < 4:
            raise GGUFValidationError("Unexpected EOF reading FLOAT32.")
        return struct.unpack("<f", b)[0]
    elif val_type == GGUF_TYPE_BOOL:
        b = f.read(1)
        if not b:
            raise GGUFValidationError("Unexpected EOF reading BOOL.")
        return bool(struct.unpack("<B", b)[0])
    elif val_type == GGUF_TYPE_STRING:
        return _read_string(f)
    elif val_type == GGUF_TYPE_ARRAY:
        type_b = f.read(4)
        count_b = f.read(8)
        if len(type_b) < 4 or len(count_b) < 8:
            raise GGUFValidationError("Unexpected EOF reading ARRAY header.")
        elem_type = struct.unpack("<I", type_b)[0]
        count = struct.unpack("<Q", count_b)[0]
        if count > 100_000:
            raise GGUFValidationError(f"Array count {count} exceeds safe limit.")
        # Only parse small or string arrays (e.g., token lists or architectures)
        elements = []
        for _ in range(count):
            elements.append(_read_value(f, elem_type))
        return elements
    elif val_type == GGUF_TYPE_UINT64:
        b = f.read(8)
        if len(b) < 8:
            raise GGUFValidationError("Unexpected EOF reading UINT64.")
        return struct.unpack("<Q", b)[0]
    elif val_type == GGUF_TYPE_INT64:
        b = f.read(8)
        if len(b) < 8:
            raise GGUFValidationError("Unexpected EOF reading INT64.")
        return struct.unpack("<q", b)[0]
    elif val_type == GGUF_TYPE_FLOAT64:
        b = f.read(8)
        if len(b) < 8:
            raise GGUFValidationError("Unexpected EOF reading FLOAT64.")
        return struct.unpack("<d", b)[0]
    else:
        raise GGUFValidationError(f"Unsupported GGUF value type: {val_type}")


def inspect_gguf_file(file_path: Union[str, Path]) -> GGUFMetadata:
    """Inspects and validates a local GGUF file, extracting key model architecture metadata.
    
    Raises:
        FileNotFoundError: If the file does not exist.
        GGUFValidationError: If the file is not a valid GGUF binary or is truncated/corrupt.
    """
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Model file does not exist: {path}")
    if not path.is_file():
        raise GGUFValidationError(f"Model path is not a regular file: {path}")

    file_size = path.stat().st_size
    if file_size < 32:
        raise GGUFValidationError(f"File size {file_size} bytes is too small for a valid GGUF.")

    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != GGUF_MAGIC:
            raise GGUFValidationError(
                f"Invalid GGUF magic bytes: expected {GGUF_MAGIC!r}, got {magic!r}. "
                "File is not a valid GGUF model."
            )

        version_b = f.read(4)
        if len(version_b) < 4:
            raise GGUFValidationError("Unexpected EOF reading GGUF version.")
        version = struct.unpack("<I", version_b)[0]
        if version not in (2, 3):
            raise GGUFValidationError(f"Unsupported GGUF version: {version}. Expected version 2 or 3.")

        counts_b = f.read(16)
        if len(counts_b) < 16:
            raise GGUFValidationError("Unexpected EOF reading tensor and metadata counts.")
        tensor_count, kv_count = struct.unpack("<QQ", counts_b)

        kv_data: Dict[str, Any] = {}
        for _ in range(kv_count):
            try:
                key = _read_string(f)
                val_type_b = f.read(4)
                if len(val_type_b) < 4:
                    raise GGUFValidationError(f"Unexpected EOF reading value type for key {key!r}.")
                val_type = struct.unpack("<I", val_type_b)[0]
                val = _read_value(f, val_type)
                kv_data[key] = val
            except (GGUFValidationError, struct.error) as e:
                # If EOF occurs during large tokenizer tables, keep what was parsed so far
                break

    # Extract standard metadata fields
    arch = str(kv_data.get("general.architecture", "unknown"))
    model_name = str(kv_data.get("general.name", path.stem))
    
    # Quantization
    file_type_val = kv_data.get("general.file_type")
    quant = "Unknown"
    if isinstance(file_type_val, int):
        quant = GGUF_FILE_TYPES.get(file_type_val, f"TYPE_{file_type_val}")
    elif "general.quantization_version" in kv_data or "q4_k" in path.name.lower():
        # Fallback to name heuristic if file_type not set
        if "q4_k_m" in path.name.lower():
            quant = "Q4_K_M"
        elif "q4_0" in path.name.lower():
            quant = "Q4_0"
        elif "q8_0" in path.name.lower():
            quant = "Q8_0"

    # Context length, block count, etc.
    ctx_len = int(
        kv_data.get(f"{arch}.context_length", kv_data.get("general.context_length", 4096))
    )
    blocks = int(
        kv_data.get(f"{arch}.block_count", kv_data.get("general.block_count", 0))
    )
    embed_len = int(
        kv_data.get(f"{arch}.embedding_length", kv_data.get("general.embedding_length", 0))
    )
    ff_len = int(
        kv_data.get(f"{arch}.feed_forward_length", kv_data.get("general.feed_forward_length", 0))
    )
    heads = int(
        kv_data.get(f"{arch}.attention.head_count", kv_data.get("general.attention.head_count", 0))
    )
    chat_tmpl = kv_data.get("tokenizer.chat_template")
    if chat_tmpl is not None:
        chat_tmpl = str(chat_tmpl)

    return GGUFMetadata(
        path=path,
        version=version,
        tensor_count=tensor_count,
        kv_count=kv_count,
        file_size_bytes=file_size,
        architecture=arch,
        model_name=model_name,
        quantization=quant,
        context_length=ctx_len,
        block_count=blocks,
        embedding_length=embed_len,
        feed_forward_length=ff_len,
        head_count=heads,
        chat_template=chat_tmpl,
        all_kv=kv_data,
    )
