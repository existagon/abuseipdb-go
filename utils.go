package abuseipdbgo

import (
	"fmt"
	"time"
)

type BulkReportBuilder struct {
	Reports []BulkReportLine
}

type BulkReportLine struct {
	IP         string
	Categories []ReportCategory
	Date       time.Time
	Comment    string
}

// Create a new BulkReportBuilder for formatting BulkReport input
func NewBulkReportBuilder() *BulkReportBuilder {
	return &BulkReportBuilder{Reports: []BulkReportLine{}}
}

// Add a new Report to the Bulk Report
func (b *BulkReportBuilder) AddReport(ip string, categories []ReportCategory, date time.Time, comment string) *BulkReportBuilder {
	b.Reports = append(b.Reports, BulkReportLine{
		IP:         ip,
		Categories: categories,
		Date:       date,
		Comment:    comment,
	})

	return b
}

func (b *BulkReportBuilder) Build() string {
	csvStr := "IP,Categories,ReportDate,Comment\n"

	for _, report := range b.Reports {
		csvStr += fmt.Sprintf("%s,\"%s\",%s,\"%s\"\n", report.IP, categoryArrayToCommaString(report.Categories), report.Date.Format(time.RFC3339), report.Comment)
	}

	return csvStr
}
