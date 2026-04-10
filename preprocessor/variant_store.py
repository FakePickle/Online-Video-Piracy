"""
preprocessor/variant_store.py

Manages the on-disk storage of variant_0 / variant_1 HLS segment pairs.

Directory layout expected (created by segmenter.create_variant_pair):

    <base_dir>/
        variant_0/
            seg_00000.ts
            seg_00001.ts
            ...
            playlist.m3u8
        variant_1/
            seg_00000.ts
            seg_00001.ts
            ...
            playlist.m3u8

The edge segment_server uses VariantStore to resolve
(segment_index, variant) → absolute Path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


class VariantStore:
    """
    Read-only view over a pre-built variant_0 / variant_1 segment directory.

    Parameters
    ----------
    base_dir:
        Root directory containing 'variant_0' and 'variant_1' sub-directories.
    segment_prefix:
        Filename prefix used by the segmenter (default ``"seg"``).
    """

    VARIANTS = (0, 1)

    def __init__(self, base_dir: str | Path, segment_prefix: str = "seg") -> None:
        self.base_dir = Path(base_dir)
        self.prefix   = segment_prefix
        self._cache: dict[tuple[int, int], Path] = {}
        self._count: Optional[int] = None

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    def _seg_name(self, index: int) -> str:
        return f"{self.prefix}_{index:05d}.ts"

    def get_segment_path(self, segment_index: int, variant: int) -> Path:
        """
        Return the absolute path for the given segment index and variant.

        Raises
        ------
        ValueError  if variant ∉ {0, 1}.
        FileNotFoundError  if the segment file does not exist on disk.
        """
        if variant not in self.VARIANTS:
            raise ValueError(f"variant must be 0 or 1, got {variant!r}")

        key = (segment_index, variant)
        if key not in self._cache:
            path = self.base_dir / f"variant_{variant}" / self._seg_name(segment_index)
            if not path.exists():
                raise FileNotFoundError(
                    f"Segment {segment_index} variant {variant} not found: {path}"
                )
            self._cache[key] = path

        return self._cache[key]

    def segment_exists(self, segment_index: int, variant: int) -> bool:
        """Return True if the segment file exists on disk."""
        if variant not in self.VARIANTS:
            return False
        path = self.base_dir / f"variant_{variant}" / self._seg_name(segment_index)
        return path.exists()

    # ------------------------------------------------------------------
    # Inventory
    # ------------------------------------------------------------------

    def segment_count(self) -> int:
        """Number of segment pairs available (determined from variant_0)."""
        if self._count is None:
            v0_dir = self.base_dir / "variant_0"
            if not v0_dir.is_dir():
                self._count = 0
            else:
                self._count = len(sorted(v0_dir.glob(f"{self.prefix}_*.ts")))
        return self._count

    def all_segment_indices(self) -> list[int]:
        """Return sorted list of all available segment indices."""
        return list(range(self.segment_count()))

    def playlist_path(self, variant: int) -> Path:
        """Return the .m3u8 playlist path for the given variant."""
        if variant not in self.VARIANTS:
            raise ValueError(f"variant must be 0 or 1, got {variant!r}")
        return self.base_dir / f"variant_{variant}" / "playlist.m3u8"

    # ------------------------------------------------------------------
    # Bulk reads (used by evaluation)
    # ------------------------------------------------------------------

    def get_all_paths(self, variant: int) -> list[Path]:
        """Return all segment paths for the given variant, in order."""
        return [self.get_segment_path(i, variant) for i in self.all_segment_indices()]

    def read_segment(self, segment_index: int, variant: int) -> bytes:
        """Read and return the raw bytes of a segment file."""
        return self.get_segment_path(segment_index, variant).read_bytes()

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"VariantStore(base_dir={self.base_dir!r}, "
            f"segments={self.segment_count()})"
        )
