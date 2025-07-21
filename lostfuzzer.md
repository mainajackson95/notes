LostFuzzer: Passive URL Fuzzing & Nuclei DAST for Bug Hunters
A Bash script for automated nuclei dast scanning by using passive urls
coffinxp
coffinxp

Following
3 min read
·
Mar 8, 2025
291


9






Introduction
Web application security testing is a crucial part of Penetration testing and bug hunting. Automating the reconnaissance and dynamic testing makes the process faster and save our lots of time. In this article i will introduce an automated URL fuzzing tool built using gau, uro, httpx-toolkit and nuclei to extract, filter and test passive URLs effectively.

Why This Tool?
Existing tools like ParamSpider often generate imbalanced URLs containing invalid or excessive parameters such as:

http://testphp.vulnweb.com/listproducts.php?artist=FUZZ&cat=FUZZ
This breaks Nuclei DAST scans or any automation scan because every query needs a valid parameter. The URL has too many FUZZ placeholders This makes it harder for Nuclei to properly process and test each parameter because valid query structures are needed for effective scanning.

That’s why I built this automation to extract only valid URLs with full query parameters ensuring they are correctly formatted for security testing.

✅ Extraction of valid URLs with real query parameters
✅ Removal of imbalanced or fuzzed queries
✅ Validation of live URLs before scanning
✅ Proper execution of Nuclei DAST for precise results

This approach makes bug hunting faster, cleaner and more effective 🚀.

Prerequisites
Before using this script ensure that the following tools are installed:

gau — Extracts URLs from passive sources
uro — Filters duplicate and redundant URLs
httpx-toolkit — Checks live URLs
nuclei — Performs DAST scanning
Installation
GitHub - coffinxp/lostfuzzer: A Bash script for automated nuclei dast scanning by using passive…
A Bash script for automated nuclei dast scanning by using passive urls - coffinxp/lostfuzzer
github.com

Clone the repository and set up the script:

git clone https://github.com/coffinxp/lostfuzzer.git
cd lostfuzzer
chmod +x lostfuzzer.sh
Usage
Run the script with the following command:

./lostfuzzer.sh
You’ll be asked to provide:

A target domain or a file containing a list of subdomains
The script will then:

Fetch passive URLs using gau in parallel for multiple subdomains.
Filter URLs that contain query parameters.
Check which URLs are live using httpx-toolkit.
Run Nuclei DAST scans for vulnerabilities.
Save results for manual testing.
Output Files
The tool generates structured output files for easy analysis:

📁 filtered_urls.txt — Contains extracted URLs with valid query parameters for further manual testing
📁 nuclei_results.txt — Stores results of the nuclei DAST scans

Example Output
[INFO] Fetching URLs with gau...
[INFO] Filtering URLs with query parameters...
[INFO] Checking live URLs using httpx-toolkit...
[INFO] Running Nuclei DAST scan...
[SUCCESS] Results saved in nuclei_results.txt

Advantages of This Approach
Time-efficient: Automates multiple steps of reconnaissance.
Accuracy-focused: Ensures only valid URLs are scanned.
Scalability: Works with large domain lists as well.
You can also watch this video where I showed the complete practicle of this method:


Conclusion
Automating URL scanning is key for bug hunting and pentesting. This tool makes the process faster more accurate and reduces false positives, allowing security pros to focus on real threats.

Upnext: If you found this helpful, you’ll definitely want to check out my article S3 Bucket Recon: Finding Exposed AWS Buckets Like a Pro! It’s a practical guide loaded with dorks, tools and real techniques to uncover misconfigured cloud storage 👇

S3 Bucket Recon: Finding Exposed AWS Buckets Like a Pro!
From Discovery to Exploitation: A Complete Guide to S3 Bucket Recon
infosecwriteups.com

Disclaimer
The content provided in this article is for educational and informational purposes only. Always ensure you have proper authorization before conducting security assessments. Use this information responsibly
