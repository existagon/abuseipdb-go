# abuseipdb-go
An [AbuseIPDB](https://abuseipdb.com) API library for Go

<img src="https://img.shields.io/github/go-mod/go-version/existentiality/abuseipdb-go">

# Usage
Add the library to your project with `go get`
```
go get github.com/existentiality/abuseipdb-go
```

Import the module
```go
import "github.com/existentiality/abuseipdb-go"
```

Create the client
```go
client := abuseipdbgo.New("YOUR_API_KEY_HERE")
```

## Functions

### Checking an IP
```go
// Check the IP "1.1.1.1" for reports within the last 30 days 
client.Check("1.1.1.1", 30)
```

### Reporting an IP
```go
// Report the IP "127.0.0.1" for an SSH Brute Force attack
client.Report("127.0.0.1", []ReportCategory{CategorySSH, CategoryBruteForce}, "SSH Brute Force: <logs>")
```

### Getting the reports of an IP
```go
// Get reports for the IP "1.1.1.1" on page 1 with 25 results per page
// Within the last 30 days
client.GetReports("1.1.1.1", 1, 25, 30)
```

### Checking the reports of an IP Block
```go
// Check the IP Block "127.0.0.0/24" (127.0.0.0-127.0.0.255) for recent reports within the past 30 days
client.CheckBlock("127.0.0.0/24", 30)
```

### Getting an IP Blacklsit
```go
// Get a blacklist of 10,000 IPs
client.GetBlacklist(10000)
```

### Bulk reporting several IPs
```go
toReport := NewBulkReportBuilder().
		AddReport("127.0.0.1", []ReportCategory{CategoryBlogSpam}, time.Now(), "Blog Spam").
		AddReport("127.0.0.3", []ReportCategory{CategorySSH, CategoryBruteForce}, time.Now(), "SSH Brute Force").
		Build()

client.BulkReport(toReport)
```

### Clearing reports of an IP
```go
// Clear all of your account's reports on the IP "1.1.1.1"
client.ClearAddress("1.1.1.1")
```