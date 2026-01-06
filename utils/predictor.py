import logging
from joblib import load
import os
from typing import Dict

_MODEL_CACHE: Dict[str, object] = {}

def load_model(path='models/model.joblib'):
    if path in _MODEL_CACHE:
        return _MODEL_CACHE[path]
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model file not found at '{path}'. Place your model.joblib file at this path.")
    model = load(path)
    _MODEL_CACHE[path] = model
    return model

def predict_url(url, model_path='models/url_model.joblib'):
    """Predict a single URL with the cached model."""
    model = load_model(model_path)
    return _model_predict(model, [url])

def predict_email(sender_email: str, subject: str, body: str, model_path='models/email_model.joblib'):
    """Predict email content using the specified model."""
    model = load_model(model_path)
    content = " ".join(filter(None, [sender_email, subject, body])).strip()
    payload = [content or "empty"]
    return _model_predict(model, payload)

def _model_predict(model, payload):
    """Run `predict` and optionally `predict_proba` on the given payload."""
    try:
        pred = model.predict(payload)
        label = str(pred[0])
    except Exception as e:
        logging.exception("Model prediction raised an exception")
        raise RuntimeError(f"Model prediction failed: {e}")

    confidence = _calculate_confidence(model, payload, label)
    return {'label': label, 'confidence': confidence}

def _calculate_confidence(model, payload, label):
    try:
        if hasattr(model, 'predict_proba'):
            probs = model.predict_proba(payload)[0]
            if hasattr(model, 'classes_'):
                classes = list(model.classes_)
                if label in classes:
                    return float(probs[classes.index(label)])
            return float(max(probs))
        return 0.5
    except Exception as e:
        logging.exception("Confidence calculation raised an exception")
        return 0.5
