#!/usr/bin/env python3
import requests
import time
import threading
import queue
import cv2
import numpy as np
import json
from urllib.parse import urljoin

NUM_CLIENTS = 100
SEGMENTS_PER_CLIENT = 20


def simulate_playback_with_pts(segment_path):
    """
    Decode a segment, read frame timestamps (PTS), simulate actual playback pacing,
    and compute real playback FPS and dropped frames.
    """
    cap = cv2.VideoCapture(segment_path)
    pts_list = []
    frames = []

    # Step 1: Extract frames + PTS timestamps
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        pts = cap.get(cv2.CAP_PROP_POS_MSEC) / 1000.0  # seconds
        if pts > 0:
            pts_list.append(pts)
        frames.append(frame)
    cap.release()

    if len(pts_list) < 2:
        return {
            "frames_presented": len(pts_list),
            "frames_dropped": 0,
            "playback_fps": 0,
            "playback_duration": 0
        }

    # Step 2: Simulate playback pacing
    start_wall = time.time()
    presented = 0
    dropped = 0
    last_present_time = start_wall

    base_pts = pts_list[0]

    for i, pts in enumerate(pts_list):
        target_wall = start_wall + (pts - base_pts)
        now = time.time()

        if now > target_wall + 0.03:  # 30ms late display threshold
            dropped += 1
            continue  # frame skipped

        if now < target_wall:
            time.sleep(target_wall - now)

        presented += 1
        last_present_time = time.time()

    playback_duration = last_present_time - start_wall
    playback_fps = presented / playback_duration if playback_duration > 0 else 0

    return {
        "frames_presented": presented,
        "frames_dropped": dropped,
        "playback_fps": playback_fps,
        "playback_duration": playback_duration
    }


def client_worker(client_id, playlist_url, out_q, analyze_video=True):
    stats = {
        "client_id": client_id,
        "segments_succeeded": 0,
        "segments_failed": 0,
        "download_times": [],
        "segment_sizes": [],
        "video_metrics": [],
        "errors": []
    }

    try:
        playlist = requests.get(playlist_url).text
    except Exception as e:
        stats["errors"].append(f"playlist_error: {e}")
        out_q.put(stats)
        return

    # Extract segment URIs
    segs = []
    for line in playlist.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            segs.append(line)

    base = playlist_url.rsplit("/", 1)[0] + "/"
    segs = segs[:SEGMENTS_PER_CLIENT]

    for idx, seg_rel in enumerate(segs):
        seg_url = urljoin(base, seg_rel)

        t0 = time.time()
        try:
            r = requests.get(seg_url)
            if r.status_code != 200:
                stats["segments_failed"] += 1
                continue

            data = r.content
            dt = time.time() - t0
            stats["segments_succeeded"] += 1
            stats["download_times"].append(dt)
            stats["segment_sizes"].append(len(data))

            # Save temp file
            path = f"/tmp/client{client_id}_seg{idx}.ts"
            with open(path, "wb") as f:
                f.write(data)

            if analyze_video:
                vm = simulate_playback_with_pts(path)
                vm["segment_idx"] = idx
                stats["video_metrics"].append(vm)

        except Exception as e:
            stats["segments_failed"] += 1
            stats["errors"].append(f"seg_err_{idx}: {e}")

    out_q.put(stats)


def main():
    PLAYLIST_URL = "http://192.168.3.177:8000/user/user_0/playlist.m3u8"

    out_q = queue.Queue()
    threads = []

    for cid in range(NUM_CLIENTS):
        playlist_for_user = PLAYLIST_URL.replace("user_0", f"user_{cid}")
        t = threading.Thread(
            target=client_worker,
            args=(cid, playlist_for_user, out_q, True)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    results = []
    while not out_q.empty():
        results.append(out_q.get())

    # Aggregate metrics
    all_dl = [t for r in results for t in r["download_times"]]
    all_sizes = [s for r in results for s in r["segment_sizes"]]

    total_bytes = sum(all_sizes)
    total_time = max(sum(all_dl) / NUM_CLIENTS, 1)

    throughput_mbps = (total_bytes * 8) / (total_time * 1_000_000)

    # Playback FPS
    all_fps = []
    dropped = 0
    presented = 0

    for r in results:
        for vm in r["video_metrics"]:
            all_fps.append(vm["playback_fps"])
            dropped += vm["frames_dropped"]
            presented += vm["frames_presented"]

    report = {
        "clients": NUM_CLIENTS,
        "segments_per_client": SEGMENTS_PER_CLIENT,
        "total_bytes": total_bytes,
        "throughput_mbps": throughput_mbps,
        "avg_download_time": float(np.mean(all_dl)) if all_dl else 0,
        "p95_download_time": float(np.percentile(all_dl, 95)) if all_dl else 0,
        "playback": {
            "avg_playback_fps": float(np.mean(all_fps)) if all_fps else 0,
            "min_playback_fps": float(np.min(all_fps)) if all_fps else 0,
            "max_playback_fps": float(np.max(all_fps)) if all_fps else 0,
            "frames_presented": presented,
            "frames_dropped": dropped,
            "drop_rate_percent": (dropped / (presented + dropped) * 100) if presented + dropped > 0 else 0
        },
        "clients_data": results
    }

    with open("stress_report_playback.json", "w") as f:
        json.dump(report, f, indent=4)

    print("DONE. Report written to stress_report_playback.json")


if __name__ == "__main__":
    main()
