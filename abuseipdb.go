package abuseipdbgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"path/filepath"
	"strings"
	"time"
)

// CHECK: https://docs.abuseipdb.com/#check-endpoint

type internalApiCheckResponse struct {
	Data CheckResponse `json:"data"`
}

type CheckResponse struct {
	IPAddress            string            `json:"ipAddress"`
	IsPublic             bool              `json:"isPublic"`
	IPVersion            int               `json:"ipVersion"`
	IsWhitelisted        bool              `json:"isWhitelisted"`
	AbuseConfidenceScore int               `json:"abuseConfidenceScore"`
	CountryCode          string            `json:"countryCode"`
	CountryName          string            `json:"countryName"`
	UsageType            string            `json:"usageType"`
	ISP                  string            `json:"isp"`
	Domain               string            `json:"domain"`
	Hostnames            []string          `json:"hostnames"`
	TotalReports         int               `json:"totalReports"`
	NumDistinctUsers     int               `json:"numDistinctUsers"`
	LastReportedAt       time.Time         `json:"lastReportedAt"`
	Reports              []ReportCheckData `json:"reports"`
}

type ReportCheckData struct {
	ReportedAt          time.Time `json:"reportedAt"`
	Comment             string    `json:"comment"`
	Categories          []int     `json:"categories"`
	ReporterID          int       `json:"reporterId"`
	ReporterCountryCode string    `json:"reporterCountryCode"`
	ReporterCountryName string    `json:"reporterCountryName"`
}

// Get information on a specific IP Address
func (c Client) Check(ip string) (*CheckResponse, error) {
	if !validateIP(ip) {
		return nil, errors.New("invalid IP Address")
	}

	query := fmt.Sprintf("verbose=true&ipAddress=%s", ip)
	res, err := c.sendRequest("GET", "/check", query, nil)

	if err != nil {
		return nil, fmt.Errorf("error Checking IP Address: %s", err)
	}

	body, _ := io.ReadAll(res.Body)
	jsonBody := *new(internalApiCheckResponse)
	json.Unmarshal(body, &jsonBody)

	return &jsonBody.Data, err
}

// REPORTS: https://docs.abuseipdb.com/#reports-endpoint

type internalApiGetReportsResponse struct {
	Data GetReportsResponse `json:"data"`
}

type GetReportsResponse struct {
	Total           int               `json:"total"`
	Page            int               `json:"page"`
	Count           int               `json:"count"`
	PerPage         int               `json:"perPage"`
	LastPage        int               `json:"lastPage"`
	NextPageURL     string            `json:"nextPageUrl"`
	PreviousPageURL string            `json:"previousPageUrl"`
	Results         []ReportCheckData `json:"results"`
}

// Get the reports for a specific IP Address
func (c Client) GetReports(ip string, page, resultsPerPage int) (*GetReportsResponse, error) {
	// Validate Arguments
	if !validateIP(ip) {
		return nil, errors.New("invalid IP Address")
	}

	if page < 1 {
		return nil, errors.New("page must be greater than or equal to 1")
	}

	if resultsPerPage < 1 {
		return nil, errors.New("results per page must be between 25 and 100")
	}

	query := fmt.Sprintf("ipAddress=%s&page=%d&resultsPerPage=%d", ip, page, resultsPerPage)
	res, err := c.sendRequest("GET", "/reports", query, nil)

	if err != nil {
		return nil, fmt.Errorf("error getting reports: %s", err)
	}

	body, _ := io.ReadAll(res.Body)
	jsonBody := *new(internalApiGetReportsResponse)
	json.Unmarshal(body, &jsonBody)

	return &jsonBody.Data, err
}

// BLACKLIST: https://docs.abuseipdb.com/#blacklist-endpoint

type internalApiBlacklistResponse struct {
	Data []BlacklistResponse `json:"data"`
}

type BlacklistResponse struct {
	IPAddress            string    `json:"ipAddress"`
	AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
	LastReportedAt       time.Time `json:"lastReportedAt"`
}

// GetBlackList function with extra parameters, only usable through an AbuseIPDB paid plan
func (c Client) GetBlacklistSubscriber(limit, confidenceMinimum int, onlyCountries, exceptCountries []string) (*[]BlacklistResponse, error) {
	if confidenceMinimum < 25 || confidenceMinimum > 100 {
		return nil, errors.New("confidence minimum must be between 25 and 100")
	}

	query := fmt.Sprintf("limit=%d&confidenceMinimum=%d&onlyCountries=%s&exceptCountries=%s", limit, confidenceMinimum,
		strings.Join(onlyCountries, ","),
		strings.Join(exceptCountries, ","))
	res, err := c.sendRequest("GET", "/blacklist", query, nil)

	if err != nil {
		return nil, fmt.Errorf("error getting blacklist: %s", err)
	}

	body, _ := io.ReadAll(res.Body)
	jsonBody := *new(internalApiBlacklistResponse)
	json.Unmarshal(body, &jsonBody)

	return &jsonBody.Data, err
}

func (c Client) GetBlacklist(limit int) (*[]BlacklistResponse, error) {
	return c.GetBlacklistSubscriber(limit, 100, []string{}, []string{})
}

// REPORT: https://docs.abuseipdb.com/#report-endpoint

type internalApiReportResponse struct {
	Data ReportResponse `json:"data"`
}

type ReportResponse struct {
	IPAddress            string `json:"ipAddress"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
}

// Report an IP Address
// See [this link] for a list of report categories
//
// [this link]: https://www.abuseipdb.com/categories
func (c Client) Report(ip string, categories []ReportCategory, comment string) (*ReportResponse, error) {
	query := fmt.Sprintf("ip=%s&comment=%s&categories=%s", ip, comment, categoryArrayToCommaString(categories))

	res, err := c.sendRequest("POST", "/report", query, nil)

	if err != nil {
		return nil, fmt.Errorf("error reporting ip: %s", err)
	}

	body, _ := io.ReadAll(res.Body)
	jsonBody := *new(internalApiReportResponse)
	json.Unmarshal(body, &jsonBody)

	return &jsonBody.Data, err
}

// CHECK-BLOCK: https://docs.abuseipdb.com/#check-block-endpoint

type internalApiCheckBlockResponse struct {
	Data CheckBlockResponse `json:"data"`
}

type CheckBlockResponse struct {
	NetworkAddress   string            `json:"networkAddress"`
	Netmask          string            `json:"netmask"`
	MinAddress       string            `json:"minAddress"`
	MaxAddress       string            `json:"maxAddress"`
	NumPossibleHosts int               `json:"numPossibleHosts"`
	AddressSpaceDesc string            `json:"addressSpaceDesc"`
	ReportedAddress  []ReportedAddress `json:"reportedAddress"`
}

type ReportedAddress struct {
	IPAddress            string    `json:"ipAddress"`
	NumReports           int       `json:"numReports"`
	MostRecentReport     time.Time `json:"mostRecentReport"`
	AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
	CountryCode          string    `json:"countryCode"`
}

// Check an IP Subnet
//
// Note: Free Subscription can check up to a /24, Basic subscription up to a /20, and Premium subscription up to a /16
func (c Client) checkBlock(cidr string, maxAgeInDays int) (*CheckBlockResponse, error) {
	query := fmt.Sprintf("network=%s&maxAgeInDays=%d", cidr, maxAgeInDays)

	res, err := c.sendRequest("GET", "/check-block", query, nil)

	if err != nil {
		return nil, fmt.Errorf("error checking ip range: %s", err)
	}

	body, _ := io.ReadAll(res.Body)
	jsonBody := *new(internalApiCheckBlockResponse)
	json.Unmarshal(body, &jsonBody)

	return &jsonBody.Data, err
}

// BULK_REPORT: https://docs.abuseipdb.com/#bulk-report-endpoint

type internalApiBulkReportResponse struct {
	Data BulkReportResponse `json:"data"`
}

type BulkReportResponse struct {
	SavedReports   int             `json:"savedReports"`
	InvalidReports []InvalidReport `json:"invalidReports"`
}

type InvalidReport struct {
	Error     string `json:"error"`
	Input     string `json:"input"`
	RowNumber int    `json:"rowNumber"`
}

// Bulk report IP Addresses from a CSV File
//
// See the [bulk report form] for information on formatting the CSV
//
// [bulk report form]: https://www.abuseipdb.com/bulk-report
func (c Client) BulkReport(fileContent string) (*BulkReportResponse, error) {

	var reqBody bytes.Buffer
	writer := multipart.NewWriter(&reqBody)

	fileWriter, err := writer.CreateFormFile("csv", filepath.Base("report.csv"))

	if err != nil {
		return nil, fmt.Errorf("error attaching bulk report file: %s", err)
	}

	if _, err = io.Copy(fileWriter, strings.NewReader(fileContent)); err != nil {
		return nil, fmt.Errorf("error copying bulk report file: %s", err)
	}

	writer.Close()

	res, err := c.sendRequest("POST", "/bulk-report", "", &requestData{
		Body:    &reqBody,
		Headers: map[string]string{"Content-Type": writer.FormDataContentType()},
	})

	if err != nil {
		return nil, fmt.Errorf("error bulk reporting: %s", err)
	}

	body, _ := io.ReadAll(res.Body)
	jsonBody := *new(internalApiBulkReportResponse)
	json.Unmarshal(body, &jsonBody)

	return &jsonBody.Data, err
}

// CLEAR-ADDRESS: https://docs.abuseipdb.com/#clear-address-endpoint

type internalApiClearAddressResponse struct {
	Data ClearAddressResponse `json:"Data"`
}

type ClearAddressResponse struct {
	NumReportsDeleted int `json:"numReportsDeleted"`
}

// Delete all of your reports for an IP Address
func (c Client) ClearAddress(ipAddress string) (*ClearAddressResponse, error) {
	query := fmt.Sprintf("ipAddress=%s", ipAddress)

	res, err := c.sendRequest("DELETE", "/clear-address", query, nil)

	if err != nil {
		return nil, fmt.Errorf("error clearing reports: %s", err)
	}

	body, _ := io.ReadAll(res.Body)
	jsonBody := *new(internalApiClearAddressResponse)
	json.Unmarshal(body, &jsonBody)

	return &jsonBody.Data, err
}
