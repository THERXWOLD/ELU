// Package policy defines the Effect type that all built-in policy packages share.
// It lives here so access, repo, and route don't have to import each other.
package policy

// Effect is the decision a policy reaches: allow, deny, or something in between.
// All built-in packages use the same Effect type so they compose cleanly.
type Effect string

const (
	EffectAllow    Effect = "allow"
	EffectPropose  Effect = "propose"
	EffectApproval Effect = "approval"
	EffectDeny     Effect = "deny"
	EffectNever    Effect = "never"
)

// IsEffect returns true if the string is a valid effect keyword.
func IsEffect(s string) bool {
	switch Effect(s) {
	case EffectAllow, EffectPropose, EffectApproval, EffectDeny, EffectNever:
		return true
	default:
		return false
	}
}

// Stronger returns true if effect a outranks effect b.
// never > deny > approval > propose > allow
func Stronger(a, b Effect) bool { return Rank(a) > Rank(b) }

// IsSeverity checks if a string is a valid risk severity level.
func IsSeverity(s string) bool {
	switch s {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

// Rank assigns a numeric rank to each effect for comparison.
// Higher number = stronger effect.
func Rank(e Effect) int {
	switch e {
	case EffectNever:
		return 5
	case EffectDeny:
		return 4
	case EffectApproval:
		return 3
	case EffectPropose:
		return 2
	case EffectAllow:
		return 1
	default:
		return 0
	}
}
