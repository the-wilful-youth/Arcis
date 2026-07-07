#!/usr/bin/env python3
"""
Arcis Threat Intelligence - Confidence Scorer Module
Calculates a normalized, weighted average risk score from multiple security components.
"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Labels a classifier might use to mean "this is NOT phishing".
# Adjust to match whatever your ml_classifier actually emits.
SAFE_LABELS = {'safe', 'legitimate', 'benign', 'ham', 'not_phishing'}
PHISHING_LABELS = {'phishing', 'malicious', 'spam'}


class ScoreResult:
    """
    Data structure containing the final analysis report.
    """
    def __init__(
        self,
        overall_confidence: float,
        risk_level: str,
        component_scores: Dict[str, float],
        reasoning: str,
        is_phishing: bool,
        weighted_contributions: Optional[Dict[str, float]] = None,
        weights_used: Optional[Dict[str, float]] = None
    ):
        self.overall_confidence = overall_confidence  # Float between 0.0 and 1.0
        self.risk_level = risk_level                  # String: 'low', 'medium', or 'high'
        self.component_scores = component_scores      # Dictionary of individual scores
        self.reasoning = reasoning                    # String text explaining the result
        self.is_phishing = is_phishing                # Boolean flag (True/False)
        # Raw score * weight per component (sums to weighted_sum, not yet normalized)
        self.weighted_contributions = weighted_contributions or {}
        # Actual weight applied to each component after redistribution
        self.weights_used = weights_used or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to a JSON serializable dictionary."""
        return {
            "overall_confidence": self.overall_confidence,
            "risk_level": self.risk_level,
            "component_scores": self.component_scores,
            "reasoning": self.reasoning,
            "is_phishing": self.is_phishing,
            "weighted_contributions": self.weighted_contributions,
            "weights_used": self.weights_used
        }


class ConfidenceScorer:
    """
    Manages the default algorithmic weights for the phishing detector.
    Weights must sum up to approximately 1.0.
    """
    def __init__(self) -> None:
        self.weights = {
            'ml_classifier': 0.35,
            'url_analysis': 0.30,
            'sensitive_request': 0.15,
            'polite_request': 0.10,
            'short_email_risk': 0.10
        }


def _component_failed(data: Any) -> bool:
    """
    A component has genuinely FAILED only if it's None or explicitly reports
    an error. A component that ran successfully and found nothing (e.g. an
    empty dict {} because there were no URLs to check) is NOT a failure and
    must still contribute its (zero) score — otherwise its weight gets
    silently redistributed onto other components and skews the result.
    """
    if data is None:
        return True
    if isinstance(data, dict) and 'error' in data:
        return True
    return False


def _score_ml_classifier(data: Dict[str, Any]) -> float:
    """
    Returns the PROBABILITY OF PHISHING in [0, 1], regardless of which
    class label the underlying model's 'confidence' field was expressed
    relative to.

    Root cause of the old bug: `confidence` from a classifier is the
    confidence in whichever class was predicted, not necessarily the
    phishing class. Using it directly as a risk score means a legitimate
    email classified 'safe' with 97% confidence scored 0.97 (high risk) --
    the same as a phishing email classified 'phishing' with 97% confidence.
    The two opposite outcomes produced the same number.

    Fix: if the model already gives an explicit phishing probability, use
    it directly. Otherwise, use the classification label to decide whether
    `confidence` should be used as-is or inverted (1 - confidence).
    """
    # Preferred: an explicit, unambiguous phishing probability if the model provides one.
    for key in ('phishing_probability', 'phishing_score', 'p_phishing'):
        if key in data and isinstance(data[key], (int, float)):
            return max(0.0, min(1.0, data[key]))

    classification = data.get('classification')
    raw_confidence = data.get('confidence', None)

    if isinstance(raw_confidence, (int, float)):
        label = str(classification).lower() if classification is not None else None
        if label in PHISHING_LABELS:
            return max(0.0, min(1.0, raw_confidence))
        if label in SAFE_LABELS:
            return max(0.0, min(1.0, 1.0 - raw_confidence))
        # Unrecognized label: log it so mislabeled data gets caught, and
        # fall back to treating confidence as already phishing-oriented
        # (previous behavior) rather than guessing wrong silently.
        logger.warning(
            f"ml_classifier returned unrecognized classification label "
            f"'{classification}'; treating confidence={raw_confidence} as "
            f"phishing probability. Add this label to SAFE_LABELS/PHISHING_LABELS."
        )
        return max(0.0, min(1.0, raw_confidence))

    # No usable confidence value at all: fall back to a hard binary signal.
    return 1.0 if classification in PHISHING_LABELS else 0.0


def score_analysis_confidence(
    results: Dict[str, Any],
    custom_weights: Optional[Dict[str, float]] = None
) -> ScoreResult:
    """
    Calculates the final phishing probability score using a Normalized Weighted Average.

    Features:
      - Weighted algorithm combination
      - Score normalization (0.0 to 1.0 range)
      - Detailed breakdown of contributing factors
      - Graceful degradation when sub-components genuinely fail (redistributes weights)
    """
    scorer = ConfidenceScorer()
    if custom_weights is not None:
        # Validate keys exactly match expected components
        if set(custom_weights.keys()) != set(scorer.weights.keys()):
            raise ValueError(f"Custom weights keys must match {list(scorer.weights.keys())}")
        # Validate values are floats in [0.0, 1.0] and sum is ~1.0
        for k, v in custom_weights.items():
            if not isinstance(v, (int, float)) or v < 0.0 or v > 1.0:
                raise ValueError(f"Custom weight value for {k} must be a float between 0.0 and 1.0")
        if not (0.99 <= sum(custom_weights.values()) <= 1.01):
            raise ValueError("The sum of custom weights must be approximately 1.0")
        weights = custom_weights
    else:
        weights = scorer.weights

    component_scores: Dict[str, float] = {}
    weighted_contributions: Dict[str, float] = {}
    weights_used: Dict[str, float] = {}
    total_weight_used = 0.0
    weighted_sum = 0.0

    # Mathematical mapping for heuristic risk levels
    risk_map = {'high': 1.0, 'medium': 0.5, 'low': 0.0, 'none': 0.0}

    for component, data in results.items():
        # Graceful Degradation:
        # Only skip (and redistribute weight) if the component genuinely
        # failed -- None or an explicit 'error' key. A successful result
        # that happens to be empty (e.g. {} = "no URLs found") still counts
        # and contributes its real (zero) score.
        if _component_failed(data):
            logger.warning(f"Component '{component}' failed or returned an error. Skipping in weighted score.")
            continue

        weight = weights.get(component, 0.0)
        score = 0.0

        # 1. Evaluate Machine Learning Classifier Output
        if component == 'ml_classifier':
            score = _score_ml_classifier(data)

        # 2. Evaluate URL Analysis Output
        elif component == 'url_analysis':
            # Use the actual maximum risk score of any embedded URL if available
            if isinstance(data, dict) and 'max_risk_score' in data:
                score = data.get('max_risk_score', 0.0)
            else:
                summary = data.get('summary', {})
                total_urls = summary.get('total_urls', 0)
                if total_urls > 0:
                    bad_urls = summary.get('suspicious_urls', 0) + summary.get('high_risk_urls', 0)
                    # Ratio of malicious links to total links, bounded at 1.0
                    score = min(1.0, bad_urls / total_urls)
                # else: 0 URLs found -> score stays 0.0, and it now correctly
                # counts toward the weighted average instead of being dropped.

        # 3. Evaluate Natural Language Processing (NLP) / Heuristic Outputs
        elif component in ('sensitive_request', 'polite_request', 'short_email_risk'):
            score = risk_map.get(data.get('risk_level', 'low'), 0.0)

        # Track individual calculated score
        component_scores[component] = score

        # Core Formula: sum(score * weight)
        contribution = score * weight
        weighted_contributions[component] = contribution
        weights_used[component] = weight
        weighted_sum += contribution
        total_weight_used += weight

    # Score Normalization:
    # Divide by total weight used so the score dynamically scales if components fail
    overall_confidence = 0.0
    if total_weight_used > 0:
        overall_confidence = weighted_sum / total_weight_used

    # Classify Risk Level based on thresholds
    if overall_confidence < 0.3:
        risk_level = 'low'
    elif overall_confidence < 0.5:
        risk_level = 'medium'
    else:
        risk_level = 'high'

    is_phishing = overall_confidence >= 0.5
    reasoning = (
        f"Analysis finalized using {len(component_scores)} operational checks. "
        f"Aggregated threat confidence reached {overall_confidence * 100:.1f}%."
    )

    return ScoreResult(
        overall_confidence=overall_confidence,
        risk_level=risk_level,
        component_scores=component_scores,
        reasoning=reasoning,
        is_phishing=is_phishing,
        weighted_contributions=weighted_contributions,
        weights_used=weights_used
        is_phishing=is_phishing
    )