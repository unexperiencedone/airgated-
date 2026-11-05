"""Server-side KYC face checks: blink liveness + identity match.

Everything runs locally on the instructor laptop -- no cloud calls -- using three model files in
models/ (fetch them once with `python fetch_models.py`):

  * YuNet (OpenCV)            -- face detection, counts faces per frame
  * MediaPipe Face Landmarker -- eyeBlinkLeft/eyeBlinkRight blendshape scores for blink counting
  * SFace (OpenCV)            -- 128-d identity embedding for matching against the enrolled face

The phone only records frames; every decision (did they blink the requested number of times, is
it one consistent person, does that person match the enrolled face) is made here, so a modified
client page cannot simply claim it passed.
"""
import os
import secrets
import threading
from dataclasses import dataclass, field

import cv2
import numpy as np

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
YUNET_PATH = os.path.join(MODELS_DIR, "face_detection_yunet_2023mar.onnx")
LANDMARKER_PATH = os.path.join(MODELS_DIR, "face_landmarker.task")
SFACE_PATH = os.path.join(MODELS_DIR, "face_recognition_sface_2021dec.onnx")

# Blink hysteresis on the averaged eyeBlink blendshape score (0 = wide open, 1 = shut).
BLINK_CLOSED_SCORE = 0.45
BLINK_OPEN_SCORE = 0.25
# Cosine-similarity threshold for SFace recommended by OpenCV's model zoo.
MATCH_THRESHOLD = 0.363
MIN_FACE_FRAME_RATIO = 0.6
MAX_EMBEDDING_FRAMES = 12
MIN_EMBEDDING_FRAMES = 3


@dataclass
class FaceAnalysis:
    frames_total: int = 0
    frames_with_face: int = 0
    multi_face_frames: int = 0
    blinks: int = 0
    embedding: np.ndarray | None = None
    best_frame_jpeg: bytes | None = None
    blink_scores: list = field(default_factory=list)

    def liveness_failure(self, blinks_required):
        """Return a human-readable rejection reason, or None if the clip passes liveness."""
        if self.frames_total == 0:
            return "No camera frames were received."
        if self.multi_face_frames > 0:
            return "More than one face was visible. Only the student should be in frame."
        if self.frames_with_face / self.frames_total < MIN_FACE_FRAME_RATIO:
            return "Face not clearly visible. Hold the phone at eye level in good light."
        if self.embedding is None:
            return "Could not get a clear view of your face with eyes open."
        if self.blinks < blinks_required:
            return f"Liveness check failed: asked for {blinks_required} blinks, saw {self.blinks}."
        return None


class _Models:
    def __init__(self):
        missing = [p for p in (YUNET_PATH, LANDMARKER_PATH, SFACE_PATH) if not os.path.exists(p)]
        if missing:
            raise RuntimeError(
                "Face model files missing: " + ", ".join(os.path.basename(p) for p in missing)
                + ". Run `python fetch_models.py` once while online."
            )
        from mediapipe.tasks.python import BaseOptions, vision

        self.detector = cv2.FaceDetectorYN.create(YUNET_PATH, "", (320, 320), 0.8, 0.3, 5000)
        self.recognizer = cv2.FaceRecognizerSF.create(SFACE_PATH, "")
        self.landmarker = vision.FaceLandmarker.create_from_options(vision.FaceLandmarkerOptions(
            base_options=BaseOptions(model_asset_path=LANDMARKER_PATH),
            running_mode=vision.RunningMode.IMAGE,
            num_faces=1,
            output_face_blendshapes=True,
        ))


_models = None
# The OpenCV DNN objects and the MediaPipe landmarker are not safe to share across threads.
_models_lock = threading.Lock()


def _get_models():
    global _models
    if _models is None:
        _models = _Models()
    return _models


def count_blinks(scores):
    """Count open -> closed -> open transitions, ignoring frames with no face (None)."""
    blinks = 0
    state = None  # must see open eyes first so a clip that starts mid-blink doesn't count
    for score in scores:
        if score is None:
            continue
        if score <= BLINK_OPEN_SCORE:
            if state == "closed":
                blinks += 1
            state = "open"
        elif score >= BLINK_CLOSED_SCORE and state == "open":
            state = "closed"
    return blinks


def _normalize(vec):
    vec = np.asarray(vec, dtype=np.float32).reshape(-1)
    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec


def similarity(a, b):
    return float(np.dot(_normalize(a), _normalize(b)))


def embedding_to_bytes(embedding):
    return _normalize(embedding).astype(np.float32).tobytes()


def embedding_from_bytes(blob):
    return np.frombuffer(blob, dtype=np.float32)


def _sample_spread(items, count):
    """Pick up to `count` items: one at random from each of `count` equal slices of the clip.

    Sampling across the whole clip (not just its start) means a clip that begins with a photo of the
    enrolled student and continues with someone else is judged on both halves. The random pick inside
    each slice keeps an attacker from knowing which frames will be examined.
    """
    if len(items) <= count:
        return list(items)
    edges = np.linspace(0, len(items), count + 1).astype(int)
    return [items[int(lo) + secrets.randbelow(int(hi - lo))] for lo, hi in zip(edges, edges[1:])]


def analyze(frame_blobs):
    """Run detection, blink scoring and embedding over an ordered list of JPEG frames."""
    result = FaceAnalysis(frames_total=len(frame_blobs))
    features = []
    open_eye = []   # (image, face, jpeg) for every eyes-open frame; sampled across the clip below
    best_score = -1.0

    with _models_lock:
        models = _get_models()
        import mediapipe as mp

        for blob in frame_blobs:
            img = cv2.imdecode(np.frombuffer(blob, dtype=np.uint8), cv2.IMREAD_COLOR)
            if img is None:
                result.blink_scores.append(None)
                continue

            h, w = img.shape[:2]
            models.detector.setInputSize((w, h))
            _, faces = models.detector.detect(img)
            face_count = 0 if faces is None else len(faces)
            if face_count > 1:
                result.multi_face_frames += 1
            if face_count == 0:
                result.blink_scores.append(None)
                continue
            result.frames_with_face += 1
            face = max(faces, key=lambda f: f[-1])

            rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            landmarks = models.landmarker.detect(mp.Image(image_format=mp.ImageFormat.SRGB, data=rgb))
            score = None
            if landmarks.face_blendshapes:
                shapes = {c.category_name: c.score for c in landmarks.face_blendshapes[0]}
                if "eyeBlinkLeft" in shapes and "eyeBlinkRight" in shapes:
                    score = (shapes["eyeBlinkLeft"] + shapes["eyeBlinkRight"]) / 2.0
            result.blink_scores.append(score)

            if score is not None and score <= BLINK_OPEN_SCORE:
                open_eye.append((img, face, blob))

        # Identity features from eyes-open frames sampled across the whole clip (still inside the
        # lock: the recognizer is not thread-safe).
        for img, face, blob in _sample_spread(open_eye, MAX_EMBEDDING_FRAMES):
            aligned = models.recognizer.alignCrop(img, face)
            features.append(_normalize(models.recognizer.feature(aligned)))
            if face[-1] > best_score:
                best_score = face[-1]
                result.best_frame_jpeg = blob

    result.blinks = count_blinks(result.blink_scores)
    if len(features) >= MIN_EMBEDDING_FRAMES:
        # Every sampled pair must be the same person. Comparing each frame only with the clip's mean
        # is not enough: a half-and-half mix of two people scores about 0.71 against its own mean.
        matrix = np.stack(features)
        if float((matrix @ matrix.T).min()) >= MATCH_THRESHOLD:
            result.embedding = _normalize(np.mean(features, axis=0))
    return result
