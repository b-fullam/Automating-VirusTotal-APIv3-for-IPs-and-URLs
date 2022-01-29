# Automating-VirusTotal-APIv3-for-IPs-and-URLs
### Automating VirusTotal's API(v3) for IP address and URL analysis with HTML Reporting

Enter a single IP address or URL, or select either a list of IP addresses or URLs to be submitted to VirusTotal's API(v3) for analysis.

Here are the options included in the script:

``` noLineNumbers
usage: vt-ip-url-analysis.py [-h] [-s SINGLE_ENTRY] [-i IP_LIST] [-u URL_LIST] [-V]

Python Automated VT API v3 IP address and URL analysis 2.0 by Brett Fullam

optional arguments:
  -h, --help                show this help message and exit
  -s SINGLE_ENTRY, --single-entry SINGLE_ENTRY
                            ip or url for analysis
  -i IP_LIST, --ip-list IP_LIST
                            bulk ip address analysis
  -u URL_LIST, --url-list URL_LIST
                            bulk url analysis
  -V, --version             show program version
```

Here's a sample of the command to run the script using a single entry, google.com, as the input:

``` noLineNumbers
python3 vt-ip-url-analysis.py -s google.com
```

The results returned by VT's API(v3) are then filtered for high-level analysis to quickly determine whether entries are harmless or need further investigation.

![Security Automation Python DNS Lookups](https://www.brettfullam.com/static/1bc2c826633bfac4fdb3f31b637ee33e/69b48/security-automation-virustotal-api-v3.jpg)

The script also generates a hypertext link to VirusTotal's web-based GUI for each entry allowing the analyst seamless access to additional information directly from the HTML report.

The generated HTML report, named "report.html", is saved in the same directory that the Python script resides.

For more information about this script, check out my article on "[Security Automation with Python — IP address and URL analysis via VirusTotal's API v3 with HTML Reporting](https://www.brettfullam.com/security-automation-with-python-ip-address-and-url-analysis-via-virus-totals-api-v-3-with-html-reporting/)." 

## Getting Started

1. Download the script or use git to clone the repository

2. Install dependencies.  This script was created using Python3, and I've included a requirements.txt file listing the necessary dependencies.  More information on how to install dependencies for this project can be found in my article ["Security Automation with Python — IP address and URL analysis via VirusTotal's API v3 with HTML Reporting"](https://www.brettfullam.com/security-automation-with-python-ip-address-and-url-analysis-via-virus-totals-api-v-3-with-html-reporting/).

3. You'll also need to create a .env file in the same directory as the Python script. Inside the .env file add the following code and insert your VirusTotal API key as indicated:

``` noLineNumbers
API_KEY1=<insert your vt API key here>
```

> ALWAYS remember to make sure you add ".env" to your .gitignore file to keep it from being sent to github and exposing your API key in the repository.  For more information on working with .env files, take a look at Drew Seewald's article ["Using dotenv to Hide Sensitive Information in Python--Hide your passwords and API tokens to make your code more secure"](https://towardsdatascience.com/using-dotenv-to-hide-sensitive-information-in-python-77ab9dfdaac8 "Using dotenv to Hide Sensitive Information in Python").

4. I also included 2 text files for testing both the IP address and URL lists functionality.  One for URLs, target-urls.txt, which has URLs with intentional formatting errors to test the regex pattern included in the script.  One for IP addresses, target-ips.txt, which includes a mix of public and private IP addresses, as well as a handful of improperly formatted IP addresses to test the regex patterns included in the script.