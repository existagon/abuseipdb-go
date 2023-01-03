package abuseipdbgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CHECK: https://docs.abuseipdb.com/#check-endpoint

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
//
// ip: The IP Address to Check
//
// maxAgeInDays: How far back in time to check reports, (min 1, max 365) (abuseipdb default: 30)
func (c Client) Check(ip string, maxAgeInDays int) (*CheckResponse, error) {
	if !validateIP(ip) {
		return nil, errors.New("invalid IP Address")
	}

	query := formatQuery(map[string]string{
		"verbose":   "true",
		"ipAddress": ip,
	})
	res, err := c.sendRequest("GET", "/check", query, nil)

	if err != nil {
		return nil, fmt.Errorf("error Checking IP Address: %s", err)
	}
	return readBody[CheckResponse](res)
}

// REPORTS: https://docs.abuseipdb.com/#reports-endpoint

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
//
// ip: The IP Address to get reports for
//
// page: The page to check (min 1)
//
// resultsPerPage: The number of results to return per page (min 1, max 100) (abuseipdb default: 25)
//
// maxAgeInDays: How far back in time to check reports (min 1, max 365) (abuseipdb default: 30)
func (c Client) GetReports(ip string, page, resultsPerPage, maxAgeInDays int) (*GetReportsResponse, error) {
	// Validate Arguments
	if !validateIP(ip) {
		return nil, errors.New("invalid IP Address")
	}

	if page < 1 {
		return nil, errors.New("page must be greater than or equal to 1")
	}

	if resultsPerPage < 1 || resultsPerPage > 100 {
		return nil, errors.New("results per page must be between 1 and 100")
	}

	query := formatQuery(map[string]string{
		"ipAddress":      ip,
		"page":           strconv.Itoa(page),
		"resultsPerPage": strconv.Itoa(resultsPerPage),
		"maxAgeInDays":   strconv.Itoa(maxAgeInDays),
	})
	res, err := c.sendRequest("GET", "/reports", query, nil)

	if err != nil {
		return nil, fmt.Errorf("error getting reports: %s", err)
	}

	return readBody[GetReportsResponse](res)
}

// BLACKLIST: https://docs.abuseipdb.com/#blacklist-endpoint

type BlacklistResponse struct {
	IPAddress            string    `json:"ipAddress"`
	AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
	LastReportedAt       time.Time `json:"lastReportedAt"`
}

// GetBlacklist function with extra parameters that are only usable through an AbuseIPDB paid plan
//
// limit: The maximum number of IPs to list (max 10,000 for Free Plan, 100,000 for Basic, and 500,000 for Premium) (abuseipdb default: 10,000)
//
// confidenceMinimum: The minimum abuse confidence score to show in the blacklist (min 25, max 100) (abuseipdb default: 100)
//
// onlyCountries: only retrieve IPs from the specified countries
//
// exceptCountries: retreive IPs from all countries, except those listed
//
// onlyCountries and exceptCountries are mutually exclusive. Country codes should be given as ISO 3166 alpha-2 codes.
func (c Client) GetBlacklistSubscriber(limit, confidenceMinimum int, onlyCountries, exceptCountries []string) (*[]BlacklistResponse, error) {
	if confidenceMinimum < 25 || confidenceMinimum > 100 {
		return nil, errors.New("confidence minimum must be between 25 and 100")
	}

	query := formatQuery(map[string]string{
		"limit":             strconv.Itoa(limit),
		"confidenceMinimum": strconv.Itoa(confidenceMinimum),
		"onlyCountries":     strings.Join(onlyCountries, ","),
		"exceptCountries":   strings.Join(exceptCountries, ","),
	})
	res, err := c.sendRequest("GET", "/blacklist", query, nil)

	if err != nil {
		return nil, fmt.Errorf("error getting blacklist: %s", err)
	}

	return readBody[[]BlacklistResponse](res)
}

// Get a Blacklist of known malicious IPs
// Note: This endpoint has restricted parameters limited to AbuseIPDB paid subscribers, if you wish to use those, please use the GetBlacklistSubscriber function
//
// limit: The maximum number of IPs to list (max 10,000 for Free Plan) (abuseipdb default: 10,000)
func (c Client) GetBlacklist(limit int) (*[]BlacklistResponse, error) {
	return c.GetBlacklistSubscriber(limit, 100, []string{}, []string{})
}

// REPORT: https://docs.abuseipdb.com/#report-endpoint

type ReportResponse struct {
	IPAddress            string `json:"ipAddress"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
}

// Report an IP Address
//
// ip: The IP Address to report
//
// categories: A list of categories to report the IP for
//
// comment: Information related to the report (server logs, timestamps, etc.)
func (c Client) Report(ip string, categories []ReportCategory, comment string) (*ReportResponse, error) {
	query := formatQuery(map[string]string{
		"ip":         ip,
		"categories": categoryArrayToCommaString(categories),
		"comment":    comment,
	})
	res, err := c.sendRequest("POST", "/report", query, nil)

	if err != nil {
		return nil, fmt.Errorf("error reporting ip: %s", err)
	}

	return readBody[ReportResponse](res)
}

// CHECK-BLOCK: https://docs.abuseipdb.com/#check-block-endpoint

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
// cidr: The network block to check in CIDR notation (Free Subscription can check up to a /24, Basic up to a /20, and Premium up to a /16)
//
// maxAgeInDays: How far back in days to check for reports (min 1, max 365) (abuseipdb default: 30)
func (c Client) CheckBlock(cidr string, maxAgeInDays int) (*CheckBlockResponse, error) {
	query := formatQuery(map[string]string{
		"network":      cidr,
		"maxAgeInDays": strconv.Itoa(maxAgeInDays),
	})
	res, err := c.sendRequest("GET", "/check-block", query, nil)

	if err != nil {
		return nil, fmt.Errorf("error checking ip range: %s", err)
	}

	return readBody[CheckBlockResponse](res)
}

// BULK_REPORT: https://docs.abuseipdb.com/#bulk-report-endpoint

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
// It is recommended to use the BulkReportBuilder to easily generate the correct input for this method.
// Otherise, see AbuseIPDB's [bulk report form] for information on how to format the file content
//
// [bulk report form]: https://www.abuseipdb.com/bulk-report
func (c Client) BulkReport(fileContent string) (*BulkReportResponse, error) {

	// Attach the bulk report csv as a multipart form file
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

	return readBody[BulkReportResponse](res)
}

// CLEAR-ADDRESS: https://docs.abuseipdb.com/#clear-address-endpoint

type ClearAddressResponse struct {
	NumReportsDeleted int `json:"numReportsDeleted"`
}

// Delete all of your reports for an IP Address
// Note: This only deletes reports your account has made, it cannot delete reports from other accounts
//
// ip: The IP Address to clear reports for
func (c Client) ClearAddress(ip string) (*ClearAddressResponse, error) {
	query := formatQuery(map[string]string{
		"ipAddress": ip,
	})

	res, err := c.sendRequest("DELETE", "/clear-address", query, nil)

	if err != nil {
		return nil, fmt.Errorf("error clearing reports: %s", err)
	}

	return readBody[ClearAddressResponse](res)
}

// Read the response and return the body
func readBody[T CheckResponse | GetReportsResponse | []BlacklistResponse | ReportResponse | CheckBlockResponse | BulkReportResponse | ClearAddressResponse](res *http.Response) (*T, error) {
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)

	if err != nil {
		return nil, fmt.Errorf("error reading body: %s", err)
	}

	// All the API response bodies are contained in a "Data" field
	jsonBody := *new(struct{ Data T })
	if err = json.Unmarshal(body, &jsonBody); err != nil {
		return nil, fmt.Errorf("error converting response body to JSON: %s", err)
	}

	return &jsonBody.Data, nil
}
