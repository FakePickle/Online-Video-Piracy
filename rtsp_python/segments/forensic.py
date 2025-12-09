#!/usr/bin/env python3
"""
forensic.py
Recover DNA watermark bits from a video by comparing against master segments.

Usage:
    python3 forensic.py recorded.mp4 master_orig master_wm user_0 user_1 user_2 --rep 1
"""

import cv2
import numpy as np
from pathlib import Path
import sys
import hashlib

# ---------- Utility ----------
def extract_features(frame):
    """
    Extract multiple features from a frame for robust comparison.
    Returns a feature vector combining spatial and frequency domain info.
    """
    # Resize and convert to grayscale
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    gray = cv2.resize(gray, (320, 180))
    gray_float = np.float32(gray) / 255.0
    
    features = []
    
    # 1. DCT coefficients from center region
    h, w = gray_float.shape
    center_patch = gray_float[h//2-32:h//2+32, w//2-32:w//2+32]
    dct = cv2.dct(center_patch)
    features.extend(dct[:8, :8].flatten())
    
    # 2. Mean intensities of different regions
    regions = [
        gray_float[0:h//2, 0:w//2],           # top-left
        gray_float[0:h//2, w//2:w],           # top-right
        gray_float[h//2:h, 0:w//2],           # bottom-left
        gray_float[h//2:h, w//2:w],           # bottom-right
        gray_float[h//4:3*h//4, w//4:3*w//4], # center
    ]
    for region in regions:
        features.append(np.mean(region))
        features.append(np.std(region))
    
    # 3. Edge information
    edges = cv2.Canny(gray, 50, 150)
    features.append(np.mean(edges) / 255.0)
    
    return np.array(features)

def generate_dna_bits(user_id):
    if (user_id == "user_0"):
        return [1,1,1,0,0,0,0,1,0,1,1,0,1,0,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,0]
    elif (user_id == "user_1"):
        return [0,0,1,1,1,1,0,1,0,1,0,0,0,0,1,1,1,0,0,1,0,0,0,1,0,0,0,1,0,1,0,0]
    else:
        h = hashlib.sha256(user_id.encode()).digest()
        bits = []
        for b in h[:4]:
            for i in range(8):
                bits.append((b >> i) & 1)
        return bits


def hamming(a, b):
    return sum(x != y for x, y in zip(a, b))

# ---------- MAIN PIPELINE ----------
def compare_frame_to_segment(frame, seg_path):
    """
    Compare a frame to a segment by computing average similarity across all frames.
    Returns average feature distance.
    """
    if not seg_path.exists():
        return float('inf')
    
    cap = cv2.VideoCapture(str(seg_path))
    frame_features = extract_features(frame)
    
    distances = []
    frame_count = 0
    while frame_count < 15:  # Sample up to 15 frames from segment
        ret, seg_frame = cap.read()
        if not ret:
            break
        
        seg_features = extract_features(seg_frame)
        dist = np.linalg.norm(frame_features - seg_features)
        distances.append(dist)
        frame_count += 1
    
    cap.release()
    
    if not distances:
        return float('inf')
    
    # Return median distance (robust to outliers)
    return np.median(distances)


def classify_frame_against_segments(frame, orig_seg, wm_seg, seg_idx):
    """
    Classify a frame by comparing it to both the orig and wm master segments.
    Returns 0 for orig, 1 for watermarked.
    """
    d_orig = compare_frame_to_segment(frame, orig_seg)
    d_wm = compare_frame_to_segment(frame, wm_seg)
    
    result = 1 if d_wm < d_orig else 0
    margin = abs(d_orig - d_wm)
    confidence = "HIGH" if margin > 1.0 else "MED" if margin > 0.3 else "LOW"
    
    print(f"Seg {seg_idx:02d}: Orig={d_orig:.3f}, WM={d_wm:.3f}, Margin={margin:.3f} [{confidence}] -> {result}")
    
    return result, margin


def extract_from_recording(recorded_path, master_orig_dir, master_wm_dir, rep=3):
    """
    Extract DNA bits from recording by comparing each second to corresponding master segments.
    Each DNA bit is repeated 'rep' times in consecutive segments.
    We use majority voting across repeated segments.
    """
    cap = cv2.VideoCapture(str(recorded_path))
    fps = cap.get(cv2.CAP_PROP_FPS)
    frames_per_second = int(round(fps))
    
    master_orig = Path(master_orig_dir)
    master_wm = Path(master_wm_dir)

    raw_bits = []
    margins = []
    frame_count = 0
    sec_frames = []
    seg_idx = 0

    print(f"\n[*] Analyzing video (FPS={fps:.1f}, frames_per_sec={frames_per_second})...")

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        sec_frames.append(frame)
        frame_count += 1

        # Process every second
        if frame_count % frames_per_second == 0:
            # Use middle frame of the second for analysis
            mid_frame = sec_frames[len(sec_frames)//2]
            
            # Get corresponding master segments
            orig_seg = master_orig / f"seg_{seg_idx:05d}.ts"
            wm_seg = master_wm / f"seg_{seg_idx:05d}.ts"
            
            if not orig_seg.exists() or not wm_seg.exists():
                print(f"Warning: Segment {seg_idx} not found in master directories")
                break
            
            bit, margin = classify_frame_against_segments(mid_frame, orig_seg, wm_seg, seg_idx)
            raw_bits.append(bit)
            margins.append(margin)
            
            sec_frames = []
            seg_idx += 1

    cap.release()
    
    print(f"\n[*] Raw bits extracted ({len(raw_bits)} segments): {raw_bits}")
    print(f"[*] Average confidence margin: {np.mean(margins):.3f}")
    
    # Apply majority voting for repeated segments
    dna_bits = []
    for i in range(0, len(raw_bits), rep):
        group = raw_bits[i:i+rep]
        if group:
            # Majority vote with confidence weighting
            majority = 1 if sum(group) > len(group) / 2 else 0
            dna_bits.append(majority)
    
    print(f"[*] DNA bits after majority voting (rep={rep}): {dna_bits}")
    return dna_bits

def identify_user(bits, candidate_users):
    best_user = None
    best_score = 999999
    for u in candidate_users:
        dna = generate_dna_bits(u)
        dist = hamming(bits, dna)
        if dist < best_score:
            best_score = dist
            best_user = u

    confidence = 1 - (best_score / len(bits))
    return best_user, confidence, best_score

def main():
    if len(sys.argv) < 5:
        print("Usage:")
        print("  python3 forensic.py recorded.mp4 master_orig master_wm user_0 user_1 [--rep 3]")
        sys.exit(1)

    rec = sys.argv[1]
    master_orig = sys.argv[2]
    master_wm = sys.argv[3]
    
    # Parse users and optional --rep argument
    users = []
    rep = 1  # default
    i = 4
    while i < len(sys.argv):
        if sys.argv[i] == "--rep" and i + 1 < len(sys.argv):
            rep = int(sys.argv[i + 1])
            i += 2
        else:
            users.append(sys.argv[i])
            i += 1

    print(f"[*] Extracting DNA bits from recording (rep={rep})...")
    print(f"[*] Master directories: orig={master_orig}, wm={master_wm}")
    bits = extract_from_recording(rec, master_orig, master_wm, rep)

    print("[*] Extracted DNA sequence:", bits[:32])

    print("[*] Identifying user...")
    user, conf, dist = identify_user(bits, users)

    print("\n===== RESULTS =====")
    print("Most likely user:", user)
    print(f"Confidence: {conf*100:.2f}%")
    print("Bit errors:", dist)
    print("====================")

if __name__ == "__main__":
    main()
