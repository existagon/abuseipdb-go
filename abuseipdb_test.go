package abuseipdbgo

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

var apiKey = os.Getenv("ABUSEIPDB_API_KEY")

var client = New(apiKey)

func TestNewClient(t *testing.T) {
	expected := Client{
		apiKey,
	}

	if client != expected {
		t.Fatalf(`Client generated incorrectly: expected %v, got %v`, expected, client)
	}
}

func TestCheck(t *testing.T) {
	res, err := client.Check("1.1.1.1")

	if err != nil {
		panic(err)
	}

	fmt.Println(res)
}

func TestGetReports(t *testing.T) {
	page := 1

	res, err := client.GetReports("1.1.1.1", page, 100)

	if err != nil {
		panic(err)
	}

	fmt.Printf("got %d/%d reports on page %d\n", res.Count, res.Total, page)
}

func TestBlacklist(t *testing.T) {
	res, err := client.GetBlacklist(10000)

	if err != nil {
		panic(err)
	}

	fmt.Printf("got %d blacklist items\n", len(*res))
}

func TestReport(t *testing.T) {
	res, err := client.Report("127.0.0.1", []ReportCategory{CategoryPhishing, CategoryBruteForce, CategorySSH}, "api testing")

	if err != nil {
		panic(err)
	}

	fmt.Printf("successfully reported %s: now has an abuse score of %d\n", res.IPAddress, res.AbuseConfidenceScore)
}

func TestCheckBlock(t *testing.T) {
	res, err := client.checkBlock("127.0.0.0/24", 30)

	if err != nil {
		panic(err)
	}

	fmt.Printf("got %d/%d reported ip addresses from range %s: %s\n", len(res.ReportedAddress), res.NumPossibleHosts, res.NetworkAddress, res.AddressSpaceDesc)

	var reportedAddresses []string

	for _, v := range res.ReportedAddress {
		reportedAddresses = append(reportedAddresses, v.IPAddress)
	}

	fmt.Printf("reported addresses in range: %s\n", strings.Join(reportedAddresses, ","))
}

func TestBulkReport(t *testing.T) {

	csvContent := NewBulkReportBuilder().
		AddReport(BulkReportReport{
			IP:         "127.0.0.1",
			Categories: []ReportCategory{CategoryBlogSpam},
			Date:       time.Now(),
			Comment:    "Bulk Report Test 1",
		}).
		AddReport(BulkReportReport{
			IP:         "127.0.0.3",
			Categories: []ReportCategory{CategorySSH, CategoryBruteForce},
			Date:       time.Now(),
			Comment:    "Bulk Report Test 2",
		}).Build()

	fmt.Println(csvContent)

	res, err := client.BulkReport(csvContent)

	if err != nil {
		panic(err)
	}

	fmt.Printf("successfully made %d reports (%d invalid)\n", res.SavedReports, len(res.InvalidReports))
}

func TestClearAddress(t *testing.T) {
	res, err := client.ClearAddress("127.0.0.1")

	if err != nil {
		panic(err)
	}

	fmt.Printf("successfully deleted %d reports\n", res.NumReportsDeleted)
}
