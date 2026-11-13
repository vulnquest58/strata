package model

import (
	"math"
	"time"
)

// DecayModel defines the mathematical function used for confidence decay over time.
type DecayModel string

const (
	DecayModelLinear      DecayModel = "linear"
	DecayModelExponential DecayModel = "exponential"
)

// CalculateDecayFactor computes the confidence decay multiplier based on asset age in days.
// Defaults to the linear model: max(0.50, 1.0 - (age_days / 180.0) * 0.50)
func CalculateDecayFactor(ageDays float64) float64 {
	return CalculateDecayFactorWithModel(ageDays, DecayModelLinear)
}

// CalculateDecayFactorWithModel computes the decay factor using either linear or exponential formula.
// Exponential: 0.50 + 0.50 * exp(-age_days / 90.0)
func CalculateDecayFactorWithModel(ageDays float64, model DecayModel) float64 {
	if ageDays <= 0 {
		return 1.0
	}

	var decay float64
	if model == DecayModelExponential {
		decay = 0.50 + 0.50*math.Exp(-ageDays/90.0)
	} else {
		// Linear model
		decay = 1.0 - (ageDays/180.0)*0.50
		if decay < 0.50 {
			decay = 0.50
		}
	}

	if decay > 1.0 {
		decay = 1.0
	}

	return math.Round(decay*10000) / 10000
}

// CalculateEffectiveConfidence calculates EffectiveConfidence and DecayFactor for a finding using linear model.
func CalculateEffectiveConfidence(adjustedConfidence float64, discoveredAt time.Time, lastVerifiedAt *time.Time, now time.Time) (float64, float64) {
	return CalculateEffectiveConfidenceWithModel(adjustedConfidence, discoveredAt, lastVerifiedAt, now, DecayModelLinear)
}

// CalculateEffectiveConfidenceWithModel calculates EffectiveConfidence and DecayFactor specifying the decay model.
func CalculateEffectiveConfidenceWithModel(adjustedConfidence float64, discoveredAt time.Time, lastVerifiedAt *time.Time, now time.Time, model DecayModel) (float64, float64) {
	refTime := discoveredAt
	if lastVerifiedAt != nil && lastVerifiedAt.After(discoveredAt) {
		refTime = *lastVerifiedAt
	}

	ageDuration := now.Sub(refTime)
	ageDays := ageDuration.Hours() / 24.0
	if ageDays < 0 {
		ageDays = 0
	}

	factor := CalculateDecayFactorWithModel(ageDays, model)
	effective := adjustedConfidence * factor
	return math.Round(effective*10000) / 10000, factor
}
