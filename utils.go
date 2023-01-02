package abuseipdbgo

import (
	"fmt"
	"time"
)

type BulkReportBuilder struct {
	Reports []BulkReportReport
}

type BulkReportReport struct {
	IP         string
	Categories []ReportCategory
	Date       time.Time
	Comment    string
}

func NewBulkReportBuilder() *BulkReportBuilder {
	return &BulkReportBuilder{Reports: []BulkReportReport{}}
}

func (b *BulkReportBuilder) AddReport(report BulkReportReport) *BulkReportBuilder {
	b.Reports = append(b.Reports, report)

	return b
}

func (b *BulkReportBuilder) Build() string {
	csvStr := "IP,Categories,ReportDate,Comment\n"

	for _, report := range b.Reports {
		csvStr += fmt.Sprintf("%s,\"%s\",%s,\"%s\"\n", report.IP, categoryArrayToCommaString(report.Categories), report.Date.Format(time.RFC3339), report.Comment)
	}

	return csvStr
}
