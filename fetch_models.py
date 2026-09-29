"""One-time download of the face models used by face_verify.py.

Run this once while the laptop still has internet; afterwards the server runs fully offline.
Checksums are pinned so a tampered or truncated download is rejected.
"""
import hashlib
import os
import sys
import urllib.request

from face_verify import MODELS_DIR

MODELS = {
    "face_detection_yunet_2023mar.onnx": (
        "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx",
        "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
    ),
    "face_recognition_sface_2021dec.onnx": (
        "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx",
        "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79",
    ),
    "face_landmarker.task": (
        "https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/latest/face_landmarker.task",
        "64184e229b263107bc2b804c6625db1341ff2bb731874b0bcc2fe6544e0bc9ff",
    ),
}


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)
    failed = False
    for name, (url, expected) in MODELS.items():
        path = os.path.join(MODELS_DIR, name)
        if os.path.exists(path) and sha256_of(path) == expected:
            print(f"✔ {name} already present")
            continue
        print(f"↓ {name}")
        urllib.request.urlretrieve(url, path)
        if sha256_of(path) != expected:
            print(f"❌ {name}: checksum mismatch, deleting")
            os.remove(path)
            failed = True
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
