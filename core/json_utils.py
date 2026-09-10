"""core.json_utils - JSON utility aliases re-exported from core.file_utils."""

from core.file_utils import (
    _extend_file,
    _json_load,
    _json_save,
    _read_tail,
    _write_json,
)

__all__ = [
    '_json_load',
    '_json_save',
    '_write_json',
    '_extend_file',
    '_read_tail',
]
