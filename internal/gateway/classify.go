package gateway

import "strings"

// ImpactTier represents a tool's impact level from the UK AISI taxonomy.
type ImpactTier string

const (
	ImpactPerception ImpactTier = "perception"
	ImpactReasoning  ImpactTier = "reasoning"
	ImpactAction     ImpactTier = "action"
)

// Generality represents how broadly a tool can operate.
type Generality string

const (
	GeneralityNarrow  Generality = "narrow"
	GeneralityGeneral Generality = "general"
)

// RiskTier is the derived risk level for a tool.
type RiskTier string

const (
	RiskLow      RiskTier = "low"
	RiskMedium   RiskTier = "medium"
	RiskHigh     RiskTier = "high"
	RiskCritical RiskTier = "critical"
)

// ToolClassification holds the auto-classification result for a gateway tool.
type ToolClassification struct {
	ImpactTier      ImpactTier
	Generality      Generality
	RiskTier        RiskTier
	MatchedKeywords []string
}

var actionKeywords = []string{
	"write", "create", "delete", "send", "execute", "deploy",
	"transfer", "pay", "update", "modify", "post", "put",
	"patch", "remove", "install", "run", "invoke",
}

var perceptionKeywords = []string{
	"read", "get", "list", "search", "query", "fetch",
	"describe", "show", "view", "check", "status", "find",
}

var reasoningKeywords = []string{
	"analyze", "plan", "summarize", "calculate", "classify",
	"evaluate", "compare", "predict",
}

var generalKeywords = []string{
	"bash", "shell", "execute", "eval", "browser",
	"computer", "click", "navigate", "terminal",
}

var financeKeywords = []string{
	"payment", "payments", "transfer", "transfers",
	"wallet", "wallets", "crypto", "trade", "trades",
	"withdraw", "deposit", "invoice", "invoices", "checkout",
	"stripe", "coinbase", "paypal",
	"balance", "balances", "funds",
}

// ClassifyTool classifies a tool by name and description into impact,
// generality, and risk tiers using keyword matching.
func ClassifyTool(name, description string) ToolClassification {
	text := strings.ToLower(name + " " + description)
	words := tokenize(text)

	var matched []string

	// Determine generality first — general tools (bash, browser, computer_use)
	// are inherently action-capable per the AISI taxonomy.
	gen := GeneralityNarrow
	generalHits := matchWords(words, generalKeywords)
	if len(generalHits) > 0 {
		gen = GeneralityGeneral
		matched = append(matched, generalHits...)
	}

	// Determine impact tier (action > perception > reasoning)
	impact := ImpactReasoning
	actionHits := matchWords(words, actionKeywords)
	perceptionHits := matchWords(words, perceptionKeywords)

	if len(actionHits) > 0 && len(actionHits) >= len(perceptionHits) {
		impact = ImpactAction
		matched = append(matched, actionHits...)
	} else if len(perceptionHits) > 0 {
		impact = ImpactPerception
		matched = append(matched, perceptionHits...)
	} else {
		reasoningHits := matchWords(words, reasoningKeywords)
		if len(reasoningHits) > 0 {
			matched = append(matched, reasoningHits...)
		}
	}

	// General tools are inherently action-capable (bash, browser, computer_use).
	if gen == GeneralityGeneral && impact != ImpactAction {
		impact = ImpactAction
	}

	// Check finance keywords
	financeHits := matchWords(words, financeKeywords)
	hasFinance := len(financeHits) > 0
	if hasFinance {
		matched = append(matched, financeHits...)
	}

	risk := deriveRiskTier(impact, gen, hasFinance)

	return ToolClassification{
		ImpactTier:      impact,
		Generality:      gen,
		RiskTier:        risk,
		MatchedKeywords: matched,
	}
}

// deriveRiskTier computes the risk tier from impact, generality, and finance presence.
//
//	perception + narrow             = low
//	reasoning  + narrow             = low
//	perception + narrow  + finance  = medium   (read-only wallet/ledger access still leaks)
//	reasoning  + narrow  + finance  = medium
//	action     + narrow             = medium
//	action     + narrow  + finance  = high     (narrow finance actions — e.g. transfer to one address)
//	perception + general            = medium
//	reasoning  + general            = medium
//	action     + general            = high
//	action     + general + finance  = critical
func deriveRiskTier(impact ImpactTier, gen Generality, hasFinance bool) RiskTier {
	// Action + general is the worst bucket regardless of finance sign.
	if impact == ImpactAction && gen == GeneralityGeneral {
		if hasFinance {
			return RiskCritical
		}
		return RiskHigh
	}
	// Finance + narrow action: still powerful (move money) without being
	// generic. Upgrade to high, not critical.
	if impact == ImpactAction && hasFinance {
		return RiskHigh
	}
	// Read-only / reasoning access to finance signals still deserves medium:
	// balance/order history is enough to front-run or phish.
	if hasFinance && (impact == ImpactPerception || impact == ImpactReasoning) {
		return RiskMedium
	}
	if impact == ImpactAction || gen == GeneralityGeneral {
		return RiskMedium
	}
	return RiskLow
}

// tokenize splits text into words using common separators (spaces, underscores, hyphens).
func tokenize(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '_' || r == '-' || r == '/' || r == '.' || r == ','
	})
}

// matchWords checks if any token matches a keyword exactly.
func matchWords(words []string, keywords []string) []string {
	kwSet := make(map[string]struct{}, len(keywords))
	for _, kw := range keywords {
		kwSet[kw] = struct{}{}
	}
	var hits []string
	seen := make(map[string]bool)
	for _, w := range words {
		if _, ok := kwSet[w]; ok && !seen[w] {
			hits = append(hits, w)
			seen[w] = true
		}
	}
	return hits
}
