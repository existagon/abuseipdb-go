package abuseipdbgo

import (
	"fmt"
	"net"
	"strings"
)

// Check if the specified string is a valid IPv4 or IPv6 address
func validateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// Used to format categories into query strings & for bulk report
func categoryArrayToCommaString(arr []ReportCategory) string {
	var newArr []string

	for _, i := range arr {
		newArr = append(newArr, fmt.Sprint(i))
	}

	return strings.Join(newArr, ",")
}

// Convert a map of strings to a formatted HTTP query
func formatQuery(parameters map[string]string) string {
	formatted := ""

	for k, v := range parameters {
		if len(formatted) > 0 {
			formatted += "&"
		}

		formatted += fmt.Sprintf("%s=%s", k, v)
	}

	return formatted
}

func mustPanic(err error) {
	if err != nil {
		panic(err)
	}
}
