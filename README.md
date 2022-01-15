# Automating-VirusTotal-APIv3-for-IPs-and-URLs
### Automating VirusTotal's API(v3) for IP address and URL analysis with HMTL Reporting

An analyst can choose to enter a single IP address or URL, or select either a list of IP addresses or URLs to be submitted to VirusTotal's API(v3).

``` nolinenumbers

Enter: 
'1' for single IP or URL entry, 
'2' to import a list of URLs, or 
'3' to import a list of IPs:

```

The results returned by VT's API(v3) are then filtered for high-level analysis to quickly determine whether entries are harmless or need further investigation.

The script also generates a hypertext link to VirusTotal's web-based GUI for each entry allowing the analyst seamless access to additional information directly from the HTML report.

The generated HTML report, named "index.html", is saved in the same directory that the Python script resides.

## Getting Started

1. Download the script or use git to clone the repository

2. Install dependencies.  This script was created using Python3, and I've included a requirements.txt file listing the necessary dependencies.

3. I also included 2 text files for testing both the IP address and URL lists functionality.  One for URLS, target-urls.txt, which has URLs with intentional formatting errors to test the regex pattern included in the script.  One for IP addresses, target-ips.txt, which includes a mix of public and private IP addresses, as well as a handful of improperly formatted IP addresses to test the regex patterns included in the script.