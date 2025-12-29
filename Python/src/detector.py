import os
import json
import pickle
import numpy as np
from utils import log_success, log_warning, log_error


class AnomalyDetector:
    """
    Meta-driven 38-feature detector:
    - Reads models/scaler from src/models/
    - Reads feature_meta.json to build EXACT training feature vector
    - Encodes categorical columns using saved category order
    """

    def __init__(self, model_dir=None):
        if model_dir is None:
            here = os.path.dirname(os.path.abspath(__file__))
            model_dir = os.path.join(here, "models")

        self.model_dir = model_dir
        self.models = {}
        self.scaler = None
        self.meta = None

        self._debug_counter = 0

        self._load_meta()
        self._load_models()

        # Backwards compatibility if any code calls .predict()
        self.predict = self.detect

    def _load_meta(self):
        meta_path = os.path.join(self.model_dir, "feature_meta.json")
        if not os.path.exists(meta_path):
            log_warning(f"feature_meta.json not found at: {meta_path}")
            self.meta = None
            return

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                self.meta = json.load(f)
            log_success(f"Loaded feature metadata from: {meta_path}")
            log_success(f"Total features in contract: {len(self.meta.get('feature_cols', []))}")
        except Exception as e:
            log_error(f"Failed to load feature_meta.json: {e}")
            self.meta = None

    def _load_models(self):
        # scaler
        scaler_path = os.path.join(self.model_dir, "scaler.pkl")
        if os.path.exists(scaler_path):
            try:
                with open(scaler_path, "rb") as f:
                    self.scaler = pickle.load(f)
                log_success(f"Loaded feature scaler from: {scaler_path}")
            except Exception as e:
                log_warning(f"Failed to load scaler: {e}")
                self.scaler = None
        else:
            log_warning(f"Scaler not found at {scaler_path}")
            self.scaler = None

        # models
        model_files = {
            "iforest": "isolation_forest.pkl",
            "lof": "local_outlier_factor.pkl",
            "ocsvm": "one_class_svm.pkl",
        }

        loaded = 0
        for name, filename in model_files.items():
            path = os.path.join(self.model_dir, filename)
            if not os.path.exists(path):
                log_warning(f"Model not found: {path}")
                continue
            try:
                with open(path, "rb") as f:
                    self.models[name] = pickle.load(f)
                log_success(f"Loaded {name} model from: {path}")
                loaded += 1
            except Exception as e:
                log_warning(f"Could not load {name} model ({path}): {e}")

        if loaded == 0:
            log_warning("No trained models loaded. Detection will not be reliable.")

    def _encode_category(self, col: str, value: str) -> float:
        """
        Encodes categorical values using the stored category ordering in meta.
        Unknown -> -1
        """
        if not self.meta:
            return -1.0
        cats = self.meta.get("categories", {}).get(col, [])
        try:
            return float(cats.index(value))
        except ValueError:
            return -1.0

    def _features_to_vector(self, feats: dict) -> np.ndarray:
        if not self.meta:
            raise RuntimeError("feature_meta.json is missing — cannot build 38-feature vector.")

        feature_cols = self.meta.get("feature_cols", [])
        cat_cols = set(self.meta.get("cat_cols", []))

        vec = []
        for col in feature_cols:
            if col in cat_cols:
                v = str(feats.get(col, ""))
                vec.append(self._encode_category(col, v))
            else:
                v = feats.get(col, 0.0)
                try:
                    vec.append(float(v))
                except Exception:
                    vec.append(0.0)

        return np.array(vec, dtype=float)

    def detect(self, feats: dict):
        """
        Returns:
            is_attack (bool)
            confidence (float 0..1)
            votes (dict model_name -> bool)
        """
        x = self._features_to_vector(feats)

        # ===== Step 2: debug print occasionally (so you can't miss it) =====
        self._debug_counter += 1
        if self._debug_counter % 500 == 1:
            expected = len(self.meta["feature_cols"]) if self.meta else "unknown"
            print(f"[DEBUG] Feature vector length: {len(x)} (expected {expected})")
        # ==============================================================

        if self.scaler is not None:
            x = self.scaler.transform([x])[0]

        votes = {}
        preds = []

        for name, model in self.models.items():
            try:
                pred = model.predict([x])[0]  # -1 anomaly, +1 normal
                is_anom = (pred == -1)
                votes[name] = bool(is_anom)
                preds.append(is_anom)
            except Exception as e:
                log_warning(f"{name} inference failed: {e}")

        if preds:
            attack_votes = int(sum(preds))
            total_votes = int(len(preds))
            is_attack = attack_votes > (total_votes / 2)
            confidence = attack_votes / total_votes
        else:
            is_attack = False
            confidence = 0.0

        return bool(is_attack), float(confidence), votes
