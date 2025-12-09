#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path
import sys

def generate_segments(input_video, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Remove old segments
    for f in output_dir.glob("seg_*.ts"):
        f.unlink()

    print(f"[Segmenter] Generating TRUE 1-second segments for: {input_video}")

    # FORCE keyframe every 1 second
    cmd = [
        "ffmpeg", "-y",
        "-i", input_video,
        "-c:v", "libx264",
        "-preset", "fast",
        "-x264-params", "keyint=30:min-keyint=30:no-scenecut=1",
        "-force_key_frames", "expr:gte(t,n_forced*1)",   # 1-second forced I-frames
        "-c:a", "aac", "-b:a", "128k",
        "-map", "0",
        "-f", "segment",
        "-segment_time", "1",
        "-segment_format", "mpegts",
        "-reset_timestamps", "1",
        str(output_dir / "seg_%05d.ts")
    ]

    print("[Segmenter] Running FFmpeg...")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        print("[Segmenter] ERROR:")
        print(result.stderr)
    else:
        print("[Segmenter] Segmentation complete!")

    seg_count = len(list(output_dir.glob("seg_*.ts")))
    print(f"[Segmenter] Total segments produced: {seg_count}")
    return seg_count


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 segment_1s_reencode.py <input.mp4> <output_dir>")
        sys.exit(1)

    generate_segments(sys.argv[1], sys.argv[2])
