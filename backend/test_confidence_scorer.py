#!/usr/bin/env python3
"""
Unit tests for confidence scorer.
Based on the downloaded test suite.
"""

import sys
import os

# Add services folder to path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'services'))

from confidence_scorer import ConfidenceScorer, score_analysis_confidence

def test_weighted_confidence_calculation():
    """Test: Weighted algorithm combination"""
    print("Testing weighted confidence calculation...")
    
    high_risk_results = {
        'ml_classifier': {'classification': 'phishing', 'confidence': 0.9},
        'url_analysis': {
            'summary': {
                'total_urls': 2,
                'safe_urls': 0,
                'suspicious_urls': 1,
                'high_risk_urls': 1
            }
        },
        'sensitive_request': {
            'is_sensitive_request': True,
            'category': 'financial',
            'risk_level': 'high'
        },
        'polite_request': {
            'is_polite_request': True,
            'risk_level': 'high'
        },
        'short_email_risk': {
            'is_short': True,
            'risk_level': 'medium'
        }
    }
    
    result = score_analysis_confidence(high_risk_results)
    print(f"  High-risk email confidence: {result.overall_confidence:.3f}")
    print(f"  Risk level: {result.risk_level}")
    
    low_risk_results = {
        'ml_classifier': {'classification': 'legitimate', 'confidence': 0.1},
        'url_analysis': {
            'summary': {
                'total_urls': 2,
                'safe_urls': 2,
                'suspicious_urls': 0,
                'high_risk_urls': 0
            }
        },
        'sensitive_request': {
            'is_sensitive_request': False,
            'category': 'none',
            'risk_level': 'low'
        },
        'polite_request': {
            'is_polite_request': False,
            'risk_level': 'low'
        },
        'short_email_risk': {
            'is_short': False,
            'risk_level': 'low'
        }
    }
    
    low_result = score_analysis_confidence(low_risk_results)
    print(f"  Low-risk email confidence: {low_result.overall_confidence:.3f}")
    print(f"  Risk level: {low_result.risk_level}")
    
    assert result.overall_confidence > low_result.overall_confidence
    print("  ✓ PASS: Weighted algorithm correctly differentiates risk levels")
    return True


def test_component_weight_assignment():
    """Test: Appropriate weight assignment"""
    print("\nTesting component weight assignment...")
    
    scorer = ConfidenceScorer()
    weights = scorer.weights
    
    required_components = ['ml_classifier', 'url_analysis', 'sensitive_request', 'polite_request', 'short_email_risk']
    assert all(comp in weights for comp in required_components)
    
    total_weight = sum(weights.values())
    assert abs(total_weight - 1.0) < 0.001
    
    print("  ✓ PASS: Component weights properly assigned")
    return True


def test_confidence_score_normalization():
    """Test: Score normalization (0-1 range)"""
    print("\nTesting confidence score normalization...")
    
    test_cases = [
        {
            'url_analysis': {'summary': {'total_urls': 5, 'safe_urls': 0, 'suspicious_urls': 0, 'high_risk_urls': 5}},
            'sensitive_request': {'is_sensitive_request': True, 'risk_level': 'high'},
            'polite_request': {'is_polite_request': True, 'risk_level': 'high'},
            'short_email_risk': {'is_short': True, 'risk_level': 'high'}
        },
        {
            'url_analysis': {'summary': {'total_urls': 0, 'safe_urls': 0, 'suspicious_urls': 0, 'high_risk_urls': 0}},
            'sensitive_request': {'is_sensitive_request': False, 'risk_level': 'low'},
            'polite_request': {'is_polite_request': False, 'risk_level': 'low'},
            'short_email_risk': {'is_short': False, 'risk_level': 'low'}
        },
        {
            'url_analysis': {'summary': {'total_urls': 3, 'safe_urls': 1, 'suspicious_urls': 2, 'high_risk_urls': 0}},
            'sensitive_request': {'is_sensitive_request': True, 'risk_level': 'medium'},
            'polite_request': {'is_polite_request': False, 'risk_level': 'low'},
            'short_email_risk': {'is_short': False, 'risk_level': 'low'}
        }
    ]
    
    for i, test_case in enumerate(test_cases):
        result = score_analysis_confidence(test_case)
        confidence = result.overall_confidence
        assert 0.0 <= confidence <= 1.0
        
    print("  ✓ PASS: All confidence scores normalized to [0,1] range")
    return True


def test_graceful_degradation():
    """Test: Graceful degradation when components fail"""
    print("\nTesting graceful degradation with component failures...")
    
    partial_results = {
        'ml_classifier': {'error': 'API timeout'},
        'url_analysis': {
            'summary': {
                'total_urls': 1,
                'safe_urls': 0,
                'suspicious_urls': 1,
                'high_risk_urls': 0
            }
        },
        'sensitive_request': {'error': 'Analysis failed'},
        'polite_request': {
            'is_polite_request': True,
            'risk_level': 'medium'
        },
        'short_email_risk': {'error': 'Component unavailable'}
    }
    
    result = score_analysis_confidence(partial_results)
    assert 0.0 <= result.overall_confidence <= 1.0
    assert result.risk_level in ['low', 'medium', 'high']
    
    all_failed_results = {
        'ml_classifier': {'error': 'Failed'},
        'url_analysis': {'error': 'Failed'},
        'sensitive_request': {'error': 'Failed'},
        'polite_request': {'error': 'Failed'},
        'short_email_risk': {'error': 'Failed'}
    }
    
    failed_result = score_analysis_confidence(all_failed_results)
    assert 0.0 <= failed_result.overall_confidence <= 1.0
    
    print("  ✓ PASS: Graceful degradation working correctly")
    return True


def test_ml_safe_confidence_inversion():
    """Test: ML Safe classification confidence inversion"""
    print("\nTesting ML Safe classification confidence inversion...")
    
    # Legit email classified 'safe' with 95% confidence
    results = {
        'ml_classifier': {'classification': 'safe', 'confidence': 0.95},
        'url_analysis': {},
        'sensitive_request': {'risk_level': 'low'},
        'polite_request': {'risk_level': 'low'},
        'short_email_risk': {'risk_level': 'low'}
    }
    
    result = score_analysis_confidence(results)
    # ml_classifier contributes (1.0 - 0.95) * 0.35 = 0.05 * 0.35 = 0.0175
    # url_analysis (empty dict {}) contributes 0.0 * 0.30 = 0.0
    # sensitive_request contributes 0.0 * 0.15 = 0.0
    # polite_request contributes 0.0 * 0.10 = 0.0
    # short_email_risk contributes 0.0 * 0.10 = 0.0
    # Overall score = 0.0175 / 1.0 = 0.0175
    print(f"  Confidence: {result.overall_confidence:.4f}")
    assert result.overall_confidence < 0.10
    assert result.risk_level == 'low'
    print("  ✓ PASS: ML safe confidence correctly inverted to represent low phishing risk")
    return True


def main():
    print("Confidence Scorer Test Suite")
    print("=" * 60)
    test_weighted_confidence_calculation()
    test_component_weight_assignment()
    test_confidence_score_normalization()
    test_graceful_degradation()
    test_ml_safe_confidence_inversion()
    print("=" * 60)
    print("ALL TESTS PASSED")

if __name__ == "__main__":
    main()
