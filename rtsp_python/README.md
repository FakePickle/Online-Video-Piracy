# Video Watermarking & Forensics System

This system implements a video watermarking and forensics solution to track and identify users who record streaming content.

## Components

### 1. `package.py`
Creates two versions of a video:
- **Original (`out/orig/`)**: No watermark
- **Watermarked (`out/wm/`)**: Has a subtle hue shift (h=+10) and timestamp overlay

```bash
python3 package.py input_video.mp4
```

### 2. `rtsp_server.py`
RTSP server that streams frames with DNA-based fingerprinting. Each user gets a unique 32-bit DNA pattern. The server switches between original and watermarked frames based on the user's DNA.

- Each DNA bit is repeated for 3 segments (REP=3)
- Segments are 1 second each (SEG_SEC=1)
- DNA bit 0 = original frame, DNA bit 1 = watermarked frame

```bash
# Start server for a specific user
python3 rtsp_server.py out/orig/video.mp4 out/wm/video.mp4 user_0

# Client connects at: rtsp://127.0.0.1:8554/test
```

### 3. `rtsp_client.py`
Secure RTSP client that receives encrypted video stream and displays it.

```bash
python3 rtsp_client.py rtsp://127.0.0.1:8554/test user_0
```

### 4. `recorder.py` ⭐ NEW
Records the decrypted video stream and saves it as a single MP4 file. This captures the watermarked frames with the embedded DNA pattern.

```bash
# Record 30 seconds of video
python3 recorder.py rtsp://127.0.0.1:8554/test user_0 rec_output 30

# Creates:
# rec_output/
#   recorded.mp4          - The recorded video
#   recorded_dna.txt      - DNA bit metadata (ground truth)
```

### 5. `forensics.py` ⭐ NEW
Analyzes a recorded MP4 video to identify which user recorded it by detecting the hue shift pattern frame-by-frame and matching it against known user DNA patterns.

```bash
# Analyze recorded video against two candidate users
python3 forensics.py rec_output/recorded.mp4 user_0 user_1

# Output shows:
# - Detected DNA pattern (per second)
# - Match percentage for each candidate user
# - Best matching user
```

## How It Works

### DNA Fingerprinting
1. Each user gets a unique 32-bit DNA pattern derived from their user_id using SHA-256
2. Each bit represents a segment choice:
   - Bit 0 = use original frame (no watermark)
   - Bit 1 = use watermarked frame (with hue shift)
3. Each DNA bit is repeated for 3 segments for robustness

### Watermark Detection
The forensics module detects watermarks by:
1. Analyzing the hue channel in HSV color space frame-by-frame
2. Computing average hue per second (30 frames at 30 fps)
3. Using median hue as threshold to distinguish watermarked vs original frames
4. Extracting the DNA pattern from the second-by-second classification
5. Matching against known user DNA patterns with 32-second cycles

### Example User DNAs (hardcoded for testing)

```python
user_0: DNA = generate_dna_bits("user_0")
user_1: DNA = generate_dna_bits("user_1")
```

## Workflow

1. **Prepare video:**
   ```bash
   python3 package.py my_video.mp4
   ```

2. **Start RTSP server for user_0:**
   ```bash
   python3 rtsp_server.py out/orig/video.mp4 out/wm/video.mp4 user_0
   ```

3. **Record stream (as if user_0 is pirating):**
   ```bash
   python3 recorder.py rtsp://127.0.0.1:8554/test user_0 pirated_video 30
   ```

4. **Forensic analysis:**
   ```bash
   python3 forensics.py pirated_video/recorded.mp4 user_0 user_1
   ```
   
   Should identify `user_0` with high confidence.

## Notes

- The hue shift watermark is subtle (h=+10) to avoid visible quality degradation
- Detection accuracy depends on video quality and compression
- The system uses REP=3 for robustness against video editing/compression
- The 32-bit DNA allows for 4.3 billion unique users
- All encryption uses AES-GCM with user-specific keys

## Requirements

- Python 3.8+
- OpenCV (cv2)
- GStreamer with RTSP support
- PyGObject
- cryptography
- ffmpeg (for encoding)
