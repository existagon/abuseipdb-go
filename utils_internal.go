package abuseipdbgo

import (
	"fmt"
	"net"
	"strings"
)

func validateIP(ip string) bool {
	// Check IP Validity
	return net.ParseIP(ip) != nil
}

func categoryArrayToCommaString(arr []ReportCategory) string {
	var newArr []string

	for _, i := range arr {
		newArr = append(newArr, fmt.Sprint(i))
	}

	return strings.Join(newArr, ",")
}
