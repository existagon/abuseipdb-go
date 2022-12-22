package abuseipdbgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

const apiRoot = "https://api.abuseipdb.com/api/v2"

type Client struct {
	ApiKey string
}

func New(apiKey string) Client {
	return Client{ApiKey: apiKey}
}

type jsonError struct {
	Errors []struct {
		Detail string `json:"detail"`
		Status int    `json:"status"`
	} `json:"errors"`
}

func (c Client) sendRequest(method string, path string, body *[]byte) (*http.Response, error) {

	if body == nil {
		body = &[]byte{}
	}

	bodyReader := bytes.NewReader(*body)

	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", apiRoot, path), bodyReader)

	if err != nil {
		return nil, fmt.Errorf("error creating HTTP request: %s", err)
	}

	req.Header.Set("Key", c.ApiKey)
	req.Header.Set("User-Agent", "abuseipdb-go (https://github.com/existentiality/abuseipdb-go)")

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)

	if err != nil {
		return nil, fmt.Errorf("error sending HTTP request: %s", err)
	}

	if res.StatusCode == 429 {
		reset := res.Header.Get("X-RateLimit-Reset")
		unix, _ := strconv.ParseInt(reset, 0, 64)

		date := time.Unix(unix, 0)

		return nil, fmt.Errorf("you are being rate limited, your limit resets at %s", date)
	} else if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		jsonBody := *new(jsonError)
		json.Unmarshal(body, &jsonBody)

		for _, v := range jsonBody.Errors {
			return nil, fmt.Errorf("%s [%d]", v.Detail, v.Status)
		}
	}

	return res, nil
}

type CheckResponse struct {
	Data struct {
		IPAddress            string    `json:"ipAddress"`
		IsPublic             bool      `json:"isPublic"`
		IPVersion            int       `json:"ipVersion"`
		IsWhitelisted        bool      `json:"isWhitelisted"`
		AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
		CountryCode          string    `json:"countryCode"`
		CountryName          string    `json:"countryName"`
		UsageType            string    `json:"usageType"`
		ISP                  string    `json:"isp"`
		Domain               string    `json:"domain"`
		Hostnames            []string  `json:"hostnames"`
		TotalReports         int       `json:"totalReports"`
		NumDistinctUsers     int       `json:"numDistinctUsers"`
		LastReportedAt       time.Time `json:"lastReportedAt"`
		Reports              []struct {
			ReportedAt          time.Time `json:"reportedAt"`
			Comment             string    `json:"comment"`
			Categories          []int     `json:"categories"`
			ReporterID          int       `json:"reporterId"`
			ReporterCountryCode string    `json:"reporterCountryCode"`
			ReporterCountryName string    `json:"reporterCountryName"`
		} `json:"reports"`
	} `json:"data"`
}

func (c Client) Check(ip string) (*CheckResponse, error) {
	if !validateIP(ip) {
		return nil, errors.New("invalid IP Address")
	}

	path := fmt.Sprintf("/check?verbose=true&ipAddress=%s", ip)
	res, err := c.sendRequest("GET", path, nil)

	if err != nil {
		return nil, fmt.Errorf("error Checking IP Address: %s", err)
	}

	body, _ := io.ReadAll(res.Body)
	jsonBody := *new(CheckResponse)
	json.Unmarshal(body, &jsonBody)

	return &jsonBody, err
}

type ReportsResponse struct {
	Data struct {
		Total           int    `json:"total"`
		Page            int    `json:"page"`
		Count           int    `json:"count"`
		PerPage         int    `json:"perPage"`
		LastPage        int    `json:"lastPage"`
		NextPageURL     string `json:"nextPageUrl"`
		PreviousPageURL string `json:"previousPageUrl"`
		Results         []struct {
			ReportedAt          time.Time `json:"reportedAt"`
			Comment             string    `json:"comment"`
			Categories          []int     `json:"categories"`
			ReporterID          int       `json:"reporterId"`
			ReporterCountryCode string    `json:"reporterCountryCode"`
			ReporterCountryName string    `json:"reporterCountryName"`
		} `json:"results"`
	} `json:"data"`
}

func (c Client) GetReports(ip string, page int, resultsPerPage int) (*ReportsResponse, error) {
	// Validate Arguments
	if !validateIP(ip) {
		return nil, errors.New("invalid IP Address")
	}

	if page < 1 {
		return nil, errors.New("rage must be greater than or equal to 1")
	}

	if resultsPerPage < 1 {
		return nil, errors.New("results per page must be between 25 and 100")
	}

	path := fmt.Sprintf("/reports?ipAddress=%s&page=%d&resultsPerPage=%d", ip, page, resultsPerPage)
	res, err := c.sendRequest("GET", path, nil)

	if err != nil {
		return nil, fmt.Errorf("error getting reports: %s", err)
	}

	body, _ := io.ReadAll(res.Body)
	jsonBody := *new(ReportsResponse)
	json.Unmarshal(body, &jsonBody)

	return &jsonBody, err
}

// Utilities

func validateIP(ip string) bool {
	// Check IP Validity
	return net.ParseIP(ip) != nil
}
