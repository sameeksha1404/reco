"""
recommender.py — Hybrid Recommendation Engine
===============================================
Two-stage pipeline:

Stage 1 — Collaborative Filtering via Truncated SVD (Matrix Factorization)
    Builds a threat × control interaction matrix from the mapping data,
    decomposes it into latent factor spaces using Truncated SVD, then scores
    every unseen (threat, control) pair by reconstructing the matrix and
    ranking by the reconstructed affinity score.

Stage 2 — Content-Based Filtering via TF-IDF + Cosine Similarity
    Builds feature vectors for each threat (category + weight bucket) and
    each control (name tokens + effectiveness bucket), computes cosine
    similarity between threat and control feature spaces, and uses this
    as a fallback / blending signal.

Final Score — Weighted Hybrid Blend
    final_score = α × cf_score + β × cb_score + γ × ml_score + δ × base_score
    where α = 0.45, β = 0.20, γ = 0.15, δ = 0.20 by default

    This means the engine blends collaborative filtering, content-based
    similarity, and a supervised ML score learned from known threat-control
    mappings, while still leveraging original domain base scores.


Collaborative Filtering (CF) → good when historical data exists
Content-Based (CB) → good for new/unseen threats
ML Model → learns complex patterns
Base Score → domain knowledge (real-world mapping)
"""

import math
import re
from typing import Any

import numpy as np
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import normalize


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tokenize(text: str) -> list[str]:
    """Lowercase and split on non-alphanumeric characters."""
    return re.findall(r"[a-z0-9]+", text.lower())


def _weight_bucket(w: float) -> str:
    if w >= 0.8: return "critical_weight"
    if w >= 0.65: return "high_weight"
    if w >= 0.5: return "medium_weight"
    return "low_weight"


def _effectiveness_bucket(e: float) -> str:
    if e >= 0.8: return "highly_effective"
    if e >= 0.6: return "moderately_effective"
    return "low_effectiveness"


# ── Engine ────────────────────────────────────────────────────────────────────

class HybridRecommendationEngine:
    """
    Hybrid CF + CB recommendation engine for threat → control ranking.

    Attributes
    ----------
    n_factors : int
        Number of latent factors for SVD decomposition. Higher = more
        expressive but risks overfitting on sparse data.
    alpha : float
        Weight of collaborative filtering signal in final blend (0–1).
    beta : float
        Weight of original base score in final blend (0–1).
        Remaining weight (1 - alpha - beta) goes to content-based signal.
    """

    def __init__(self, n_factors: int = 8, alpha: float = 0.45, beta: float = 0.2, gamma: float = 0.15):
        self.n_factors = n_factors
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.cb_weight = 1.0 - alpha - beta - gamma
        if self.cb_weight < 0:
            raise ValueError("alpha + beta + gamma must be <= 1.0")

        # Will be populated by fit()
        self._threat_ids: list[int] = []
        self._control_ids: list[int] = []
        self._threat_idx: dict[int, int] = {}
        self._control_idx: dict[int, int] = {}

        self._interaction_matrix: np.ndarray | None = None
        self._reconstructed: np.ndarray | None = None

        self._threat_features: np.ndarray | None = None
        self._control_features: np.ndarray | None = None
        self._cb_similarity: np.ndarray | None = None

        self._ml_model: GradientBoostingRegressor | None = None
        self._ml_scores: np.ndarray | None = None

        self._base_scores: dict[tuple[int, int], float] = {}
        self._fitted = False

    # ── Fit ───────────────────────────────────────────────────────────────────

    def fit(
        self,
        threats: dict[int, dict],
        controls: dict[int, dict],
        threat_map: list[dict],
    ) -> None:
        """
        Train the engine on the available data.

        Parameters
        ----------
        threats  : {id: {id, name, category, weight}}
        controls : {id: {id, name, effectiveness}}
        threat_map : list of {threat_id, control_id, effectiveness, mapping_impact, ...}
        """
        self._threat_ids = sorted(threats.keys())
        self._control_ids = sorted(controls.keys())
        self._threat_idx = {t: i for i, t in enumerate(self._threat_ids)}
        self._control_idx = {c: i for i, c in enumerate(self._control_ids)}

        n_threats = len(self._threat_ids)
        n_controls = len(self._control_ids)

        # ── Stage 1: Build interaction matrix ────────────────────────────────
        # Each cell = effectiveness × mapping_impact (the "rating")
        # Zero means no known interaction (not necessarily bad — just unknown)
        R = np.zeros((n_threats, n_controls), dtype=np.float32)

        for row in threat_map:
            tid = int(row["threat_id"])
            cid = int(row["control_id"])
            eff = float(row["effectiveness"])
            imp = float(row["mapping_impact"])
            base = round(eff * imp, 4)
            self._base_scores[(tid, cid)] = base

            if tid in self._threat_idx and cid in self._control_idx:
                ti = self._threat_idx[tid]
                ci = self._control_idx[cid]
                R[ti, ci] = base

        self._interaction_matrix = R

        # ── Stage 1: Truncated SVD decomposition ─────────────────────────────
        # R ≈ U · Σ · Vt  where U = threat latent factors, V = control latent factors
        # We cap n_factors to avoid rank issues on small matrices
        actual_factors = min(self.n_factors, n_threats - 1, n_controls - 1)
        svd = TruncatedSVD(n_components=actual_factors, random_state=42)
        U = svd.fit_transform(R)          # (n_threats × n_factors)
        Vt = svd.components_              # (n_factors × n_controls)

        # Reconstruct full matrix — this fills in "predicted ratings" for
        # zero cells, which is the core of collaborative filtering
        self._reconstructed = np.dot(U, Vt)  # (n_threats × n_controls)

        # ── Stage 2: Content-based feature matrix ─────────────────────────────
        # Threat features: category tokens + weight bucket
        vocab: dict[str, int] = {}

        def _get_or_add(token: str) -> int:
            if token not in vocab:
                vocab[token] = len(vocab)
            return vocab[token]

        threat_token_lists: list[list[str]] = []
        for tid in self._threat_ids:
            t = threats[tid]
            tokens = (
                _tokenize(t["category"])
                + _tokenize(t["name"])
                + [_weight_bucket(t["weight"])]
            )
            threat_token_lists.append(tokens)
            for tok in tokens:
                _get_or_add(tok)

        # Control features: name tokens + effectiveness bucket
        control_token_lists: list[list[str]] = []
        for cid in self._control_ids:
            c = controls[cid]
            tokens = (
                _tokenize(c["name"])
                + [_effectiveness_bucket(c["effectiveness"])]
            )
            control_token_lists.append(tokens)
            for tok in tokens:
                _get_or_add(tok)

        V = len(vocab)

        # Build TF (term frequency) vectors — simple bag of words
        def _to_bow(token_list: list[str]) -> np.ndarray:
            vec = np.zeros(V, dtype=np.float32)
            for tok in token_list:
                if tok in vocab:
                    vec[vocab[tok]] += 1.0
            # TF normalization
            s = vec.sum()
            if s > 0:
                vec /= s
            return vec

        T_feat = np.array([_to_bow(tl) for tl in threat_token_lists])   # (n_threats × V)
        C_feat = np.array([_to_bow(cl) for cl in control_token_lists])  # (n_controls × V)

        # L2-normalize for cosine similarity
        T_feat = normalize(T_feat, norm="l2")
        C_feat = normalize(C_feat, norm="l2")

        self._threat_features = T_feat
        self._control_features = C_feat

        # Cosine similarity between every threat and every control
        self._cb_similarity = cosine_similarity(T_feat, C_feat)  # (n_threats × n_controls)

        # ── Stage 3: Train a supervised ML model for score prediction ───────
        X_train: list[np.ndarray] = []
        y_train: list[float] = []
        for row in threat_map:
            tid = int(row["threat_id"])
            cid = int(row["control_id"])
            if tid in self._threat_idx and cid in self._control_idx:
                ti = self._threat_idx[tid]
                ci = self._control_idx[cid]
                feature_row = np.concatenate([
                    T_feat[ti],
                    C_feat[ci],
                    [threats[tid]["weight"], controls[cid]["effectiveness"]],
                ])
                X_train.append(feature_row)
                y_train.append(self._base_scores[(tid, cid)])

        if X_train:
            X_train_arr = np.vstack(X_train)
            y_train_arr = np.array(y_train, dtype=np.float32)
            self._ml_model = GradientBoostingRegressor(
                random_state=42,
                n_estimators=50,
                max_depth=3,
                learning_rate=0.1,
            )
            self._ml_model.fit(X_train_arr, y_train_arr)

            # Predict scores for every possible threat-control pair
            threat_weights = np.array([threats[tid]["weight"] for tid in self._threat_ids], dtype=np.float32)
            control_effectiveness = np.array([controls[cid]["effectiveness"] for cid in self._control_ids], dtype=np.float32)

            T_ext = np.repeat(T_feat, n_controls, axis=0)
            C_ext = np.tile(C_feat, (n_threats, 1))
            W_ext = np.repeat(threat_weights, n_controls).reshape(-1, 1)
            E_ext = np.tile(control_effectiveness, n_threats).reshape(-1, 1)
            X_all = np.hstack([T_ext, C_ext, W_ext, E_ext])
            self._ml_scores = self._ml_model.predict(X_all).reshape(n_threats, n_controls).astype(np.float32)
        else:
            self._ml_model = None
            self._ml_scores = np.zeros((n_threats, n_controls), dtype=np.float32)

        self._fitted = True

    # ── Recommend ─────────────────────────────────────────────────────────────

    def recommend(self, threat_id: int, top_k: int = 3) -> list[dict[str, Any]]:
        """
        Return top-k recommended controls for a given threat.

        Scoring formula (per control c for threat t):
            cf_score  = reconstructed[t_idx, c_idx]  (SVD collaborative signal)
            cb_score  = cb_similarity[t_idx, c_idx]  (content feature similarity)
            base_score = original effectiveness × mapping_impact (domain knowledge)
            final     = α·cf + (1-α-β)·cb + β·base

        All three signals are min-max normalized to [0,1] before blending
        so no single signal dominates by scale.
        """
        if not self._fitted:
            raise RuntimeError("Engine not fitted. Call fit() first.")

        if threat_id not in self._threat_idx:
            return []

        ti = self._threat_idx[threat_id]
        n_controls = len(self._control_ids)

        cf_row = self._reconstructed[ti]       # raw CF scores for all controls
        cb_row = self._cb_similarity[ti]       # cosine similarity scores

        # Min-max normalize each signal independently
        def _minmax(arr: np.ndarray) -> np.ndarray:
            lo, hi = arr.min(), arr.max()
            if hi == lo:
                return np.zeros_like(arr)
            return (arr - lo) / (hi - lo)

        cf_norm = _minmax(cf_row)
        cb_norm = _minmax(cb_row)

        # Base scores (only for known pairs; 0 for unknown)
        base_row = np.array([
            self._base_scores.get((threat_id, self._control_ids[ci]), 0.0)
            for ci in range(n_controls)
        ], dtype=np.float32)
        base_norm = _minmax(base_row)

        ml_row = self._ml_scores[ti] if self._ml_scores is not None else np.zeros(n_controls, dtype=np.float32)
        ml_norm = _minmax(ml_row)

        # Weighted blend including learned ML score
        final_scores = (
            self.alpha * cf_norm
            + self.cb_weight * cb_norm
            + self.beta * base_norm
            + self.gamma * ml_norm
        )

        # Rank all controls by final score descending
        ranked_indices = np.argsort(final_scores)[::-1]

        results = []
        for ci in ranked_indices[:top_k]:
            cid = self._control_ids[ci]
            base = self._base_scores.get((threat_id, cid), 0.0)
            results.append({
                "control_id": cid,
                "cf_score": round(float(cf_norm[ci]), 4),
                "cb_score": round(float(cb_norm[ci]), 4),
                "base_score": round(float(base_norm[ci]), 4),
                "final_score": round(float(final_scores[ci]), 4),
                # Use original base score as the "impact" for downstream risk calc
                "impact": round(base if base > 0 else float(cb_norm[ci]) * 0.5, 4),
            })

        return results

    # ── Similar threats ───────────────────────────────────────────────────────

    def similar_threats(self, threat_id: int, top_k: int = 3) -> list[tuple[int, float]]:
        """
        Find the most similar threats to a given threat using latent CF space.
        Useful for explaining WHY a control was recommended
        ('controls that worked for similar threats').
        """
        if not self._fitted or threat_id not in self._threat_idx:
            return []

        ti = self._threat_idx[threat_id]
        # Use SVD-transformed U matrix for latent similarity
        # (recompute from reconstructed — approximation)
        threat_vecs = self._reconstructed  # (n_threats × n_controls) as proxy
        scores = cosine_similarity([threat_vecs[ti]], threat_vecs)[0]
        scores[ti] = -1  # exclude self

        ranked = np.argsort(scores)[::-1][:top_k]
        return [(self._threat_ids[i], round(float(scores[i]), 4)) for i in ranked]

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def explain(self, threat_id: int, control_id: int) -> dict:
        """
        Return a breakdown of why a control was recommended for a threat,
        showing each signal's contribution to the final score.
        """
        if not self._fitted:
            return {}

        ti = self._threat_idx.get(threat_id)
        ci = self._control_idx.get(control_id)
        if ti is None or ci is None:
            return {}

        cf_raw = float(self._reconstructed[ti, ci])
        cb_raw = float(self._cb_similarity[ti, ci])
        base = self._base_scores.get((threat_id, control_id), 0.0)

        ml_raw = float(self._ml_scores[ti, ci]) if self._ml_scores is not None else 0.0
        return {
            "collaborative_filtering_raw": round(cf_raw, 4),
            "content_based_cosine_raw": round(cb_raw, 4),
            "supervised_ml_raw": round(ml_raw, 4),
            "base_domain_score": round(base, 4),
            "alpha": self.alpha,
            "cb_weight": self.cb_weight,
            "beta": self.beta,
            "gamma": self.gamma,
        }
