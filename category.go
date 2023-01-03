package abuseipdbgo

type ReportCategory int

const (
	// Altering DNS records resulting in improper redirection.
	CategoryDNSCompromise ReportCategory = iota + 1
	// Falsifying domain server cache (cache poisoning).
	CategoryDNSPosioning
	// Fraudulent orders.
	CategoryFraudOrders
	// Participating in distributed denial-of-service (usually part of botnet).
	CategoryDDoSAttack
	// Participating in an FTP Brute Force attack
	CategoryFTPBruteForce
	// Oversized IP packet.
	CategoryPingOfDeath
	// Phishing websites and/or email.
	CategoryPhishing
	// Participating in VoIP Fraud
	CategoryFraudVoIP
	// Open proxy, open relay, or Tor exit node.
	CategoryOpenProxy
	// Comment/forum spam, HTTP referer spam, or other CMS spam.
	CategoryWebSpam
	// Spam email content, infected attachments, and phishing emails.
	CategoryEmailSpam
	// CMS blog comment spam.
	CategoryBlogSpam
	// Conjunctive category.
	CategoryVPNIP
	// Scanning for open ports and vulnerable services.
	CategoryPortScan
	// Participating in Hacking
	CategoryHacking
	// Attempts at SQL injection.
	CategorySQLInjection
	// Email sender spoofing.
	CategorySpoofing
	// Credential brute-force attacks on webpage logins and services like SSH, FTP, SIP, SMTP, RDP, etc. This category is seperate from DDoS attacks.
	CategoryBruteForce
	// Webpage scraping (for email addresses, content, etc) and crawlers that do not honor robots.txt. Excessive requests and user agent spoofing can also be reported here.
	CategoryBadWebBot
	// Host is likely infected with malware and being used for other attacks or to host malicious content. The host owner may not be aware of the compromise. This category is often used in combination with other attack categories.
	CategoryExploitedHost
	// Attempts to probe for or exploit installed web applications such as a CMS like WordPress/Drupal, e-commerce solutions, forum software, phpMyAdmin and various other software plugins/solutions.
	CategoryWebAppAttack
	// Secure Shell (SSH) abuse. Use this category in combination with more specific categories.
	CategorySSH
	// Abuse was targeted at an "Internet of Things" type device. Include information about what type of device was targeted in the comments.
	CategoryIoTTargeted
)
