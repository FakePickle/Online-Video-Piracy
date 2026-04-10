# 01-Parity — HLS Forensic Watermarking Research System

A CDN-edge forensic watermarking prototype for HLS video. Embeds
per-subscriber fingerprints into live streams using an XOR parity chain so
that a pirated recording can be traced back to the leaking subscriber — even
under recompression, resize, and multi-user collusion attacks.

---

## Table of Contents

1. [How it works](#how-it-works)
2. [Repository layout](#repository-layout)
3. [Prerequisites](#prerequisites)
4. [Setup](#setup)
5. [Running the tests](#running-the-tests)
6. [Module walkthrough](#module-walkthrough)
   - [Preprocessor](#preprocessor)
   - [Key server](#key-server)
   - [Edge parity selector](#edge-parity-selector)
   - [Forensics pipeline](#forensics-pipeline)
   - [Evaluation](#evaluation)
7. [End-to-end example script](#end-to-end-example-script)
8. [Key parameters](#key-parameters)
9. [Known limitations / open questions](#known-limitations--open-questions)

---

## How it works

```
                   ┌─────────────────────────────────────────────┐
  Source video ──► │ Preprocessor: create variant_0 / variant_1  │
                   └───────────────────┬─────────────────────────┘
                                       │ (offline, once per title)
                   ┌───────────────────▼─────────────────────────┐
                   │ Key Server: register subscribers, store k_sub │
                   └───────────────────┬─────────────────────────┘
                                       │ k_sub on demand (edge pulls)
                   ┌───────────────────▼─────────────────────────┐
   Subscriber ───► │ Edge: HKDF → AES-CTR → RS(64,42) → XOR chain│
                   │        select variant_0 or variant_1 per seg  │
                   └───────────────────┬─────────────────────────┘
                                       │ personalised HLS stream
                   ┌───────────────────▼─────────────────────────┐
  Pirated copy ──► │ Forensics: histogram classify → XOR inverse  │
                   │            → RS decode → DB match             │
                   └─────────────────────────────────────────────┘
```

### Storage model (+100% overhead)

Per segment, exactly **two files** are stored on the CDN origin:

```
segment_i_v0.ts   ← original, unmodified
segment_i_v1.ts   ← DCT-shifted variant (±Δ=3 on selected AC coefficients)
```

This is **+100% storage overhead** — double the vanilla single-copy baseline,
and half of a classical A/B scheme (which would store two *independently*
watermarked copies rather than one original + one modified).

The **fingerprint is the sequence of which variant was served**, not a
watermark embedded in the video bits:

```
v₁ = random {0, 1}
for each segment i:
    serve segment_i_v{v_i}          ← original or watermarked
    v_{i+1} = v_i XOR f_i          ← advance the parity chain
```

This has three important consequences:

1. **Security** — a subscriber receiving their personalised stream cannot tell
   which segments are v0 and which are v1 without the secret mask used during
   embedding (PSNR >45 dB guarantee: the two variants are visually identical).

2. **Forensic detection** — the lab computes differential colour histograms
   between adjacent segments of the leaked copy.  A detectable difference
   means they came from different variants → that transition encodes a `1` bit.

3. **Collusion** — two subscribers averaging their streams get a mixture of
   v0 and v1 pixels for segments where they received different variants.
   The RS(64,42) code tolerates up to 11 symbol errors (≈17.2% BER), so even
   a 3-user average is expected to be attributable (empirical BER ≈ 8%).

### Parity chain (core algorithm)

```
k_u  = HKDF-SHA256(K_vendor ‖ K_sub)
raw  = AES-CTR(k_u)[:42 bytes]          # subscriber identity material
cw   = RS(64,42).encode(raw)            # 64-byte codeword over GF(2⁸)
bits = serialise(cw)                    # 512 bits  (8 bits × 64 bytes)

v₁        ← random {0,1}
v_{i+1}   = v_i XOR bits[i-1]          # XOR chain; one bit per segment

forensics: f_i = v_i XOR v_{i+1}       # recovers the embedded bits
```

**Error tolerance** — RS(64,42) corrects up to 11 codeword-byte errors.  
With 8 bits per RS symbol that is 88 bit errors out of 512 total ≈ **17.2% BER**, below the stated 18% bound.

---

## Repository layout

```
01-parity/
├── edge/
│   └── parity_selector.py    ← core algorithm (HKDF, AES-CTR, RS, XOR chain)
│
├── preprocessor/
│   ├── embedder.py           ← DCT ±Δ=3 watermark embedding
│   ├── segmenter.py          ← ffmpeg wrapper → variant_0 / variant_1 .ts pairs
│   └── variant_store.py      ← (segment_index, variant) → Path resolver
│
├── key_server/
│   ├── hkdf.py               ← key derivation utilities
│   ├── subscriber_db.py      ← thread-safe in-memory subscriber registry
│   └── api.py                ← Flask REST API for edge nodes
│
├── forensics/
│   ├── extractor.py          ← HSV histogram comparison → variant sequence
│   ├── reed_solomon.py       ← RS decode wrapper with diagnostics
│   └── matcher.py            ← Hamming DB lookup → ranked suspect list
│
├── evaluation/
│   ├── attack_sim.py         ← T1 identity / T2 recompression / T3 resize / T4 collusion
│   ├── ber_measure.py        ← BER computation per attack type
│   ├── load_test.py          ← N concurrent subscribers, latency + cache metrics
│   └── metrics_collect.py   ← real-time CSV metrics + report generation
│
├── tests/
│   └── test_parity.py        ← 34 unit tests for edge/parity_selector.py
│
└── requirements.txt
```

---

## Prerequisites

| Dependency | Version | Purpose |
|-----------|---------|---------|
| Python | ≥ 3.11 | runtime |
| [uv](https://docs.astral.sh/uv/) | any | virtual-env & package management |
| [ffmpeg](https://ffmpeg.org/download.html) | ≥ 5.0 | HLS segmentation, attack simulation |
| (optional) A test video | any `.mp4` | preprocessor & evaluation |

### Install ffmpeg

**Windows** — download a static build from https://ffmpeg.org/download.html and add the `bin/` directory to your `PATH`, **or** use winget:
```
winget install ffmpeg
```

**macOS**
```
brew install ffmpeg
```

**Linux (Debian/Ubuntu)**
```
sudo apt install ffmpeg
```

---

## Setup

```bash
# 1. Clone
git clone https://github.com/FakePickle/Online-Video-Piracy
cd Online-Video-Piracy

# 2. Create virtual environment with uv
uv venv .venv

# 3. Activate (Windows PowerShell)
.venv\Scripts\Activate.ps1
# Activate (Windows CMD)
.venv\Scripts\activate.bat
# Activate (macOS / Linux)
source .venv/bin/activate

# 4. Install dependencies
uv pip install -r requirements.txt
```

All commands below assume the virtual environment is **activated**
(or prefix them with `.venv/Scripts/python.exe` on Windows /
`.venv/bin/python` on macOS/Linux).

---

## Running the tests

```bash
pytest tests/test_parity.py -v
```

Expected output: **34 passed** in < 1 s.

The tests cover:
- HKDF key derivation (determinism, uniqueness)
- AES-CTR fingerprint generation
- Bit serialisation round-trips
- XOR chain correctness and double-embed
- RS(64,42) encode/decode with 0 and 11 symbol errors
- Full pipeline: subscriber key → variants → extract bits → RS decode → attribution

---

## Module walkthrough

### Preprocessor

Creates the two segment variants that are stored on the CDN origin.
Requires **ffmpeg** and an input video.

```python
from preprocessor.segmenter import create_variant_pair

variant0_segs, variant1_segs = create_variant_pair(
    input_path      = "source.mp4",
    output_base     = "segments/",
    mask_key        = bytes.fromhex("your-32-byte-mask-key-hex"),
    segment_duration = 2,           # seconds per HLS segment
)
# Output:
#   segments/variant_0/seg_00000.ts  …  playlist.m3u8
#   segments/variant_1/seg_00000.ts  …  playlist.m3u8
```

Access stored segments via `VariantStore`:

```python
from preprocessor.variant_store import VariantStore

store = VariantStore("segments/")
print(store.segment_count())                    # e.g. 150
path  = store.get_segment_path(index=0, variant=1)
```

Test the DCT embedder standalone (no video file needed):

```python
import numpy as np
from preprocessor.embedder import WatermarkEmbedder, PSNRError

embedder = WatermarkEmbedder(mask_key=b"test-mask-key-32bytes-padding!!!")
frame    = np.random.randint(0, 256, (720, 1280, 3), dtype=np.uint8)

# embed_frame returns (result_frame, psnr).
# If PSNR < 45 dB the original frame is returned unchanged (psnr = inf).
result, psnr = embedder.embed_frame(frame, frame_idx=0)
print(f"PSNR: {psnr:.2f} dB")   # expect > 45 dB; inf = frame was not modified

# embed_video raises PSNRError if the segment-level mean PSNR is too low.
try:
    stats = embedder.embed_video("segment.mp4", "segment_v1.mp4")
    print(stats)
    # {'frames_processed': 60, 'frames_embedded': 58, 'frames_reverted': 2,
    #  'mean_psnr': 47.3, 'min_psnr': 45.8}
except PSNRError as e:
    print(f"Segment rejected: {e}")
    # Lower delta or raise variance_threshold and retry.
```

---

### Key server

Start the REST API:

```bash
# Set secrets via environment variables
export K_VENDOR_HEX=<64-char hex string>   # 32-byte vendor key
export API_TOKEN=my-secret-token

python key_server/api.py
# Listening on http://0.0.0.0:8080
```

Register a subscriber and fetch their key:

```bash
# Register
curl -s -X POST http://localhost:8080/subscribers \
     -H "Authorization: Bearer my-secret-token" \
     -H "Content-Type: application/json" \
     -d '{"subscriber_id": "alice"}' | python -m json.tool

# Fetch key (edge node calls this)
curl -s http://localhost:8080/subscribers/alice/key \
     -H "Authorization: Bearer my-secret-token" | python -m json.tool

# List all subscribers
curl -s http://localhost:8080/subscribers \
     -H "Authorization: Bearer my-secret-token"
```

Use the DB directly in Python (no HTTP needed for testing):

```python
from key_server.subscriber_db import SubscriberDB

K_VENDOR = bytes.fromhex("aabbcc..." )   # 32 bytes
db = SubscriberDB(k_vendor=K_VENDOR)
db.register("alice")
db.register("bob")

record = db.get("alice")
print(record.k_u.hex())              # 32-byte derived key
print(record.raw_fingerprint.hex())  # 42-byte identity material
```

---

### Edge parity selector

The core algorithm.  The edge calls this for every subscriber session:

```python
from edge.parity_selector import compute_variant_sequence

# Returns [(0, 1), (1, 0), (2, 0), (3, 1), ...] — (segment_index, variant)
pairs = compute_variant_sequence(
    subscriber_id = "alice",
    k_vendor      = K_VENDOR,
    k_sub         = record.k_sub,
    n_segments    = 1025,       # MIN_SEGMENTS for full double-embed
)

for seg_idx, variant in pairs:
    segment_path = store.get_segment_path(seg_idx, variant)
    # serve segment_path to the subscriber
```

---

### Forensics pipeline

Given a leaked video (or list of leaked segment files), identify the subscriber:

```python
from forensics.extractor   import SegmentExtractor
from forensics.reed_solomon import RSDecoder
from forensics.matcher      import FingerprintMatcher

# 1. Extract fingerprint bits from the leaked segments
extractor = SegmentExtractor(variant_store=store)
fp_bits, confidences = extractor.extract_fingerprint_bits(leaked_segment_paths)

# 2. RS decode
decoder = RSDecoder()
diag    = decoder.decode_with_diagnostics(fp_bits)
print(f"BER estimate: {diag['ber_estimate']:.3f}")
print(f"RS success:   {diag['success']}")

# 3. Match against subscriber DB
matcher = FingerprintMatcher(db=db, k_vendor=K_VENDOR)
results, _ = matcher.identify_by_fp_bits(fp_bits, top_k=5)

for r in results:
    print(f"  #{r.rank}  {r.subscriber_id:20s}  "
          f"hamming={r.hamming_dist}  conf={r.confidence:.3f}  "
          f"{'EXACT' if r.exact_match else ''}")
```

---

### Evaluation

**Run attack simulations** (requires ffmpeg):

```python
from evaluation.attack_sim import AttackType, apply_attack

# T1: identity (no modification)
apply_attack(AttackType.T1_IDENTITY,      ["leaked.mp4"], "out/t1.mp4")

# T2: recompression at 500kbps
apply_attack(AttackType.T2_RECOMPRESSION, ["leaked.mp4"], "out/t2.mp4", bitrate="500k")

# T3: resize ×0.5 then restore
apply_attack(AttackType.T3_RESIZE,        ["leaked.mp4"], "out/t3.mp4", scale_factor=0.5)

# T4: 3-user collusion averaging
apply_attack(AttackType.T4_COLLUSION,
             ["alice.mp4", "bob.mp4", "carol.mp4"], "out/t4.mp4")
```

**Measure BER per attack:**

```python
from evaluation.ber_measure import run_all_attacks, print_ber_table

results = run_all_attacks(
    leaked_segment_paths = [Path("leaked_seg_00000.ts"), ...],
    variant_store        = store,
    ground_truth_fp_bits = fp_bits_ground_truth,
    output_dir           = Path("eval_output/"),
)
print_ber_table(results)
```

Expected output:
```
Attack             Bit BER  Sym BER  RS OK  Attr?
--------------------------------------------------
identity            0.0000   0.0000    YES    YES
recompression       0.0050   0.0156    YES    YES
resize              0.0000   0.0000    YES    YES
collusion           0.0800   0.1406    YES    YES
```

**Load test:**

```python
from evaluation.load_test import run_load_test

# Register 50 test subscribers
db.register_bulk([f"sub_{i:04d}" for i in range(50)])

result = run_load_test(
    n_subscribers            = 50,
    db                       = db,
    k_vendor                 = K_VENDOR,
    variant_store            = store,
    segments_per_subscriber  = 513,   # one full RS pass
    cache_size               = 256,
)
print(result.summary())
```

**Collect live metrics:**

```python
from evaluation.metrics_collect import MetricsCollector

collector = MetricsCollector(output_csv="metrics.csv")
collector.start()

# Inside your serving loop:
collector.record_segment(
    subscriber_id = "alice",
    segment_index = 5,
    variant       = 1,
    latency_ms    = 18.3,
    bytes_served  = 49152,
    cache_hit     = True,
)

collector.stop()
print(collector.report().summary())
```

---

## End-to-end example script

```python
#!/usr/bin/env python
"""
end_to_end_demo.py  — runs the full pipeline on a local video file.

Usage:
    python end_to_end_demo.py source.mp4
"""
import sys
from pathlib import Path

from key_server.hkdf         import generate_k_vendor, derive_mask_key
from key_server.subscriber_db import SubscriberDB
from preprocessor.segmenter  import create_variant_pair
from preprocessor.variant_store import VariantStore
from edge.parity_selector    import compute_variant_sequence
from forensics.extractor     import SegmentExtractor
from forensics.matcher       import FingerprintMatcher

video = Path(sys.argv[1])
out   = Path("demo_output")

# --- 1. Generate secrets ---
K_VENDOR = generate_k_vendor()
mask_key = derive_mask_key(K_VENDOR)
print(f"K_vendor = {K_VENDOR.hex()[:16]}...")

# --- 2. Register subscribers ---
db = SubscriberDB(k_vendor=K_VENDOR)
alice = db.register("alice")
bob   = db.register("bob")

# --- 3. Pre-process video ---
print("Segmenting video...")
v0_segs, v1_segs = create_variant_pair(video, out / "segments", mask_key)
store = VariantStore(out / "segments")
print(f"  {store.segment_count()} segment pairs created")

# --- 4. Simulate Alice streaming ---
print("Generating Alice's variant sequence...")
pairs = compute_variant_sequence("alice", K_VENDOR, alice.k_sub,
                                  n_segments=store.segment_count())
alice_segments = [store.get_segment_path(i, v) for i, v in pairs]

# --- 5. Forensic identification ---
print("Running forensic extraction...")
extractor = SegmentExtractor(variant_store=store)
fp_bits, _ = extractor.extract_fingerprint_bits(alice_segments)

matcher = FingerprintMatcher(db, K_VENDOR)
results, diag = matcher.identify_by_fp_bits(fp_bits)

print(f"\nRS decode: {'OK' if diag['success'] else 'FAIL'} "
      f"(BER ≈ {diag.get('ber_estimate', 0):.3f})")
print("Top suspects:")
for r in results[:3]:
    print(f"  #{r.rank} {r.subscriber_id:20s}  "
          f"hamming={r.hamming_dist}  {'<-- CORRECT' if r.exact_match else ''}")
```

Run it:
```bash
python end_to_end_demo.py path/to/your/video.mp4
```

---

## Key parameters

| Constant | Value | Where | Meaning |
|----------|-------|-------|---------|
| `RS_DATA` | 42 bytes | `edge/parity_selector.py` | Subscriber fingerprint size |
| `RS_TOTAL` | 64 bytes | same | RS codeword size |
| `BITS_PER_SYMBOL` | 8 | same | HLS segments per RS byte |
| `SEGMENTS_PER_PASS` | 512 | same | Segments needed per RS pass |
| `MIN_SEGMENTS` | 1025 | same | Segments for full double-embed |
| `DELTA` | 3 | `preprocessor/embedder.py` | DCT coefficient shift |
| `VARIANCE_THRESHOLD` | 4.0 | same | Max HSV variance for block selection |

At **2 s per segment**, one double-embedded fingerprint requires 1024 × 2 s = **2048 s ≈ 34 min** of content.  
Use shorter segment durations (e.g. 0.5 s) if you need to fit within a 5-minute window.

---

## Known limitations / open questions

1. **ABR bitrate switching** — when a subscriber switches quality mid-stream,
   the variant state `v_i` must carry over to the new bitrate's segment series.
   The current parity selector computes a flat sequence; the segment server needs
   to maintain per-subscriber `v_i` state across quality switches.

2. **Cold cache latency** — the worst-case latency when the edge must fetch a
   variant from origin is not bounded in this prototype.  Add a cache-miss
   timeout and async prefetch in `edge/cache.py`.

3. **Minimum content duration** — with RS(64,42) × 8 bits/symbol × 2 passes,
   a minimum of **2048 s** at 2 s/segment is required.  The system should refuse
   to embed fingerprints in content shorter than this threshold.

4. **Collusion math (T4)** — when 2 subscribers average their streams, the
   differential histogram sits midway between the two sets.  The exact
   analytical formula for the resulting BER as a function of colluder count
   has not been derived; `evaluation/ber_measure.py` measures it empirically.
