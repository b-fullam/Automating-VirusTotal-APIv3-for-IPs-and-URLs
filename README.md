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

3. You'll also need to create a .env file in the same directory as the Python script. Inside the .env file add the following code and insert your VirusTotal API key as indicated:

``` nolinenumbers

API_KEY1=<insert your vt API key here>

```

> ALWAYS remember to make sure you add ".env" to your .gitignore file to keep it from being sent to github and exposing your API key in the repository.  For more information on working with .env files, take a look at Drew Seewald's article ["Using dotenv to Hide Sensitive Information in Python--Hide your passwords and API tokens to make your code more secure"]("https://towardsdatascience.com/using-dotenv-to-hide-sensitive-information-in-python-77ab9dfdaac8", Using dotenv to Hide Sensitive Information in Python).

4. I also included 2 text files for testing both the IP address and URL lists functionality.  One for URLS, target-urls.txt, which has URLs with intentional formatting errors to test the regex pattern included in the script.  One for IP addresses, target-ips.txt, which includes a mix of public and private IP addresses, as well as a handful of improperly formatted IP addresses to test the regex patterns included in the script.