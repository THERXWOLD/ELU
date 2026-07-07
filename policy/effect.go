// Package policy defines the Effect type that all built-in policy packages share.
// It lives here so access, repo, and route don't have to import each other.
package policy

// Effect is the decision a policy reaches: allow, deny, or something in between.
// All built-in packages use the same Effect type so they compose cleanly.
type Effect string

const (
	// EffectAllow — let it through, no friction, no fuss.
	EffectAllow Effect = "allow"
	// EffectPropose — suggest it, but someone needs to sign off.
	EffectPropose Effect = "propose"
	// EffectApproval — needs explicit approval before anything happens.
	EffectApproval Effect = "approval"
	// EffectDeny — nope. Shut it down.
	EffectDeny Effect = "deny"
	// EffectNever — strongest possible no. Not now, not ever.
	EffectNever Effect = "never"
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
// Valid levels: low, medium, high, critical.
func IsSeverity(s string) bool {
	switch s {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

// Rank assigns a numeric rank to each effect for comparison.
// Higher number = stronger effect. Never is 5, Allow is 1.
// Zero means "I don't know what this effect is".
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
