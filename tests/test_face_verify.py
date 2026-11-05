import os
import sys
import types

import cv2
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import face_verify  # noqa: E402


@pytest.mark.parametrize("scores, expected", [
    ([0.1, 0.6, 0.1], 1),
    ([0.1, 0.6, 0.1, 0.7, 0.05], 2),
    ([0.7, 0.1, 0.7], 0),                    # clip starts mid-blink, ends mid-blink
    ([0.1, 0.6, None, 0.1], 1),              # frames without a face are skipped
    ([0.1, 0.35, 0.1, 0.35, 0.1], 0),        # squinting never crosses the closed threshold
    ([0.1, 0.5, 0.4, 0.5, 0.1], 1),          # hysteresis: one long blink counts once
])
def test_count_blinks(scores, expected):
    assert face_verify.count_blinks(scores) == expected


def test_embedding_round_trip():
    vec = np.arange(128, dtype=np.float32)
    restored = face_verify.embedding_from_bytes(face_verify.embedding_to_bytes(vec))
    assert face_verify.similarity(vec, restored) == pytest.approx(1.0)


def test_liveness_failures():
    ok = face_verify.FaceAnalysis(frames_total=10, frames_with_face=10, blinks=2, embedding=np.ones(128))
    assert ok.liveness_failure(2) is None
    assert "blinks" in ok.liveness_failure(3)
    crowd = face_verify.FaceAnalysis(frames_total=10, frames_with_face=10, multi_face_frames=1, blinks=2, embedding=np.ones(128))
    assert "More than one face" in crowd.liveness_failure(2)
    hidden = face_verify.FaceAnalysis(frames_total=10, frames_with_face=3, blinks=2, embedding=np.ones(128))
    assert "not clearly visible" in hidden.liveness_failure(2)


models_present = all(os.path.exists(p) for p in (face_verify.YUNET_PATH, face_verify.LANDMARKER_PATH, face_verify.SFACE_PATH))


@pytest.mark.skipif(not models_present, reason="run fetch_models.py first")
def test_models_reject_blank_frames():
    import cv2
    blank = cv2.imencode(".jpg", np.zeros((240, 320, 3), dtype=np.uint8))[1].tobytes()
    result = face_verify.analyze([blank] * 5)
    assert result.frames_with_face == 0
    assert result.liveness_failure(2) is not None


A, B = 50, 200   # grey levels standing in for two different people


def _analyze_clip(monkeypatch, clip):
    """clip = list of (person, blink score). The models are stubbed so only the decision logic runs."""
    ids = {A: np.eye(128)[0], B: np.eye(128)[1]}
    scores = iter(score for _, score in clip)
    ns = types.SimpleNamespace
    models = ns(
        detector=ns(setInputSize=lambda size: None,
                    detect=lambda img: (1, np.array([[0, 0, 10, 10, 0.9]], dtype=np.float32))),
        recognizer=ns(alignCrop=lambda img, face: img, feature=lambda img: ids[int(img[0, 0, 0])]),
        landmarker=ns(detect=lambda img: (lambda s: ns(face_blendshapes=[[
            ns(category_name="eyeBlinkLeft", score=s), ns(category_name="eyeBlinkRight", score=s)]]))(next(scores))),
    )
    monkeypatch.setattr(face_verify, "_get_models", lambda: models)
    return face_verify.analyze([
        cv2.imencode(".png", np.full((64, 64, 3), person, np.uint8))[1].tobytes() for person, _ in clip])


def _blinking(person):
    return ([(person, 0.05)] * 10 + [(person, 0.9)] * 2) * 3 + [(person, 0.05)] * 10


def test_same_person_passes(monkeypatch):
    result = _analyze_clip(monkeypatch, [(A, 0.05)] * 16 + _blinking(A))
    assert result.embedding is not None and result.liveness_failure(3) is None


@pytest.mark.parametrize("lead", [14, 23])
def test_person_swapped_mid_clip_fails(monkeypatch, lead):
    """Still of person A first, then person B blinking: identity must be judged across the whole clip."""
    result = _analyze_clip(monkeypatch, [(A, 0.05)] * lead + _blinking(B))
    assert result.embedding is None and result.liveness_failure(3) is not None


def test_sample_spread_covers_the_whole_clip():
    picked = face_verify._sample_spread(list(range(120)), 12)
    assert len(picked) == 12 and picked[0] < 10 and picked[-1] >= 110
    assert face_verify._sample_spread([1, 2, 3], 12) == [1, 2, 3]
