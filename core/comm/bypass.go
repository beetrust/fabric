package comm

import (
	"os"
	"strings"
)

var bypassTLSVerification = parseTLSEnv()

func parseTLSEnv() bool {
	val := strings.ToLower(strings.TrimSpace(os.Getenv("FABRIC_BYPASS_TLS_VERIFICATION")))
	switch val {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

func shouldBypassTLSVerification() bool {
	return bypassTLSVerification
}
