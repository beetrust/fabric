package msp

import (
	"os"
	"strings"
)

var bypassMSPValidation = parseBypassEnv()

func parseBypassEnv() bool {
	val := strings.ToLower(strings.TrimSpace(os.Getenv("FABRIC_BYPASS_MSP_VALIDATION")))
	switch val {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

// MSPBypassEnabled indicates whether MSP validation/loading safeguards should be skipped.
func MSPBypassEnabled() bool {
	return bypassMSPValidation
}
