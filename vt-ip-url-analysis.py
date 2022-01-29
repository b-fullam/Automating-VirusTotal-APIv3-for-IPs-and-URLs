import argparse
import time
from pathlib import Path
import requests
import re
import pandas as pd
import json
import base64
import os
import hashlib
from dotenv import load_dotenv


# //////////////////////////////////////////////
#
# Python Automated VT API v3 IP address and URL analysis 2.0
# by Brett Fullam
#
# Accepts single entries for IP address or URL
# Performs bulk IP address analysis
# Performs bulk URL Analysis
#
# Outputs HTML report with hypertext links per entry
# to VirusTotal's web-based GUI for a full report
#
# //////////////////////////////////////////////


# load_dotenv will look for a .env file and if it finds one it will load the environment variables from it
load_dotenv()

"""
/////  IMPORTANT  /////
ADD .env to gitignore to keep it from being sent to github
and exposing your API key in the repository
"""

# retrieve API key from .env file and store in a variable
API_KEY = os.getenv("API_KEY1")


# ////////////////////////////////// START Initiate the parser

parser = argparse.ArgumentParser(description="Python Automated VT API v3 IP address and URL analysis 2.0 by Brett Fullam")
parser.add_argument("-s", "--single-entry", help="ip or url for analysis")
parser.add_argument("-i", "--ip-list", help="bulk ip address analysis")
parser.add_argument("-u", "--url-list", help="bulk url analysis")
parser.add_argument("-V", "--version", help="show program version", action="store_true")

# ////////////////////////////////// END Initiate the parser


# initialize dataframe variable
dataframe = []

report_time = ' '


# ////////////////////////////////// START URL REPORT REQUEST

# this is the function that will take user input or input from a list to submit urls to VirusTotal for url reports, receive and format the returned json for generating our html reports

def urlReport(arg):

    # user input, ip or url, to be submitted for a url analysis stored in the target_url variable
    target_url = arg

    # For a url analysis report virustotal requires the "URL identifier" or base64 representation of URL to scan (w/o padding)

    # create virustotal "url identifier" from user input stored in target_url
    # Encode the user submitted url to base64 and strip the "==" from the end
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")

    # print(url_id)

    # amend the virustotal apiv3 url to include the unique generated url_id
    url = "https://www.virustotal.com/api/v3/urls/" + url_id


    # while you can enter your API key directly for the "x-apikey" it's not recommended as a "best practice" and should be stored-accessed separately in a .env file (see comment under "load_dotenv()"" for more information
    headers = {
        "Accept": "application/json",
        "x-apikey": API_KEY
    }

    response = requests.request("GET", url, headers=headers)

    # load returned json from virustotal into a python dictionary called decodedResponse
    decodedResponse = json.loads(response.text)

    # grab the epoch timestamp at run time and convert to human-readable for the html report header information
    timeStamp = time.time()

    # set report_time to a global value to share the stored value with other functions    
    global report_time

    # convert epoch timestamp to human-readable date time formatted
    report_time = time.strftime('%c', time.localtime(timeStamp))
    
    # set dataframe to a global value to share the stored value with other functions
    global dataframe

    # grab "last_analysis_date" key data to convert epoch timestamp to human readable date time formatted
    epoch_time = (decodedResponse["data"]["attributes"]["last_analysis_date"])
    
    # convert epoch time to human readable date time and store in the time_formatted variable
    # the original key last_analysis_date from the returned virustotal json will be removed and replaced with an updated last_analysis_date value that's now human readable
    time_formatted = time.strftime('%c', time.localtime(epoch_time))

    # create sha256 encoded vt "id" of each url or ip address to generate a hypertext link to a virustotal report in each table
    # create a string value of the complete url to be encoded
    UrlId_unEncrypted = ("http://" + target_url + "/")

    # begin function for encrypting our hyperlink string to sha256
    def encrypt_string(hash_string):
        sha_signature = \
            hashlib.sha256(hash_string.encode()).hexdigest()
        return sha_signature

    # store the hyperlink string to be hashed in the variable hash_string
    hash_string = UrlId_unEncrypted
    
    # encrypt and store our sha256 hashed hypertext string as
    sha_signature = encrypt_string(hash_string)
 
    # create the hypertext link to the virustotal.com report
    vt_urlReportLink = ("https://www.virustotal.com/gui/url/" + sha_signature)

    # strip the "data" and "attribute" keys from the decodedResponse dictionary and only include the keys listed within "attributes" to create a more concise list stored in a new dictionary called a_json
    filteredResponse = (decodedResponse["data"]["attributes"])

    # create an array of keys to be removed from attributes to focus on specific content for quicker/higher-level analysis
    keys_to_remove = [
        "last_http_response_content_sha256", 
        "last_http_response_code",
        "last_analysis_results",
        "last_final_url", 
        "last_http_response_content_length", 
        "url", 
        "last_analysis_date", 
        "tags", 
        "last_submission_date", 
        "threat_names",
        "last_http_response_headers",
        "categories",
        "last_modification_date",
        "title",
        "outgoing_links",
        "first_submission_date",
        "total_votes",
        "type",
        "id",
        "links",
        "trackers",
        "last_http_response_cookies",
        "html_meta"
        ]

    # iterate through the filteredResponse dictionary using the keys_to_remove array and pop to remove additional keys listed in the array
    for key in keys_to_remove:
      filteredResponse.pop(key, None)

    # create a dataframe with the remaining keys stored in the filteredResponse dictionary
    # orient="index" is necessary in order to list the index of attribute keys as rows and not as columns
    dataframe = pd.DataFrame.from_dict(filteredResponse, orient="index")
    
    # rename the column header to the submitted url
    dataframe.columns = [target_url]

    # grab "malicious" key data from last_analysis_stats to create the first part of the community_score_info
    community_score = (decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"])

    # grab the sum of last_analysis_stats to create the total number of security vendors that reviewed the URL for the second half of the community_score_info
    total_vt_reviewers = (decodedResponse["data"]["attributes"]["last_analysis_stats"]["harmless"])+(decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"])+(decodedResponse["data"]["attributes"]["last_analysis_stats"]["suspicious"])+(decodedResponse["data"]["attributes"]["last_analysis_stats"]["undetected"])+(decodedResponse["data"]["attributes"]["last_analysis_stats"]["timeout"])

    # create a custom community score using community_score and the total_vt_reviewers values
    community_score_info = str(community_score)+ ("/") + str(total_vt_reviewers) + ("  :  security vendors flagged this as malicious")

    # amend dataframe with extra community score row
    dataframe.loc['virustotal report',:] = vt_urlReportLink

    # amend dataframe with extra community score row
    dataframe.loc['community score',:] = community_score_info

    # amend dataframe with the updated last_analysis_date value stored in time_formatted that was converted from epoch to human readable
    dataframe.loc['last_analysis_date',:] = time_formatted

    # sort dataframe index in alphabetical order to put the community score at the top
    dataframe.sort_index(inplace = True)

    # set html to a global value to share the stored value with other functions
    global html

    # dataframe is output as an html table, and stored in the html variable
    html = dataframe.to_html(render_links=True, escape=False)

# ////////////////////////////////// END URL REPORT REQUEST



# ////////////////////////////////// START IMPORT URL LIST

# this function will handle importing a user defined list of urls, validate each url, and store them in an array called lst.  Then each validated entry will be submitted to the urlReport() function, and an html table will be returned for each of them and stored in an array called html_table_array. 

def urlReportLst(arg):
    print("Option 2:")
    # open user defined list from file path/name
    with open(arg) as fcontent:
        fstring = fcontent.readlines()
    # regex statement to validate/normalize the content of the user defined list
    pattern = re.compile(r'(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?')

    # initialize the lst array to store the validated list
    lst=[]

    # iterate over each line of the user defined list using the regex pattern to validate and normalize the content
    for line in fstring:
        lst.append(pattern.search(line)[0])

    # output the validated list of urls to be sent to the urlReport() function
    print("Valid URLs ")
    print(lst, "\n")

    # set dataframe to a global value to share the stored value with other functions
    global dataframe
    # set html to a global value to share the stored value with other functions
    global html

    # initialize array to store our array of html tables
    html_table_array = []

    # create and store an array of html tables using our validated list in html_table_array
    for i in lst:
        urlReport(i)
        # print(dataframe) is used to print output to the terminal to improve user experience within the terminal.  This can be commented out or removed completely if you do not want to see any output printed in the terminal for each validated entry.
        print(dataframe, "\n")
        html_table_array.append(html)

    # update html variable with our array of html tables stored in html_table_array for use with the outputHTML() function
    html = html_table_array

# ////////////////////////////////// END IMPORT URL LIST



# ////////////////////////////////// START IMPORT IP LIST

# this function will handle importing a user defined list of IPs, sort each IP as public or private IP range, and store them in separate arrays called Public_IPs or Private_IPs.  Then, since we are only interested in public IPs, only the IPs stored in the Public_IPs array will be validated and submitted to the urlReport() function.  An html table will be returned for each of the IPs and stored in an array called html_table_array. 

def urlReportIPLst(arg):
    # open user defined list from file path/name
    print("Option 3:")
    with open(arg) as fh:
        string = fh.readlines()

    # regex pattern to filter-sort Private and Public IP addresses
    pattern = re.compile(r'(^0\.)|(^10\.)|(^100\.6[4-9]\.)|(^100\.[7-9]\d\.)|(^100\.1[0-1]\d\.)|(^100\.12[0-7]\.)|(^127\.)|(^169\.254\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.0\.0\.)|(^192\.0\.2\.)|(^192\.88\.99\.)|(^192\.168\.)|(^198\.1[8-9]\.)|(^198\.51\.100\.)|(^203.0\.113\.)|(^22[4-9]\.)|(^23[0-9]\.)|(^24[0-9]\.)|(^25[0-5]\.)')

    # initializing variables to store our sorted public and private IPs
    Private_IPs =[]
    Public_IPs=[]

    # iterate over each line of the user defined list using the regex pattern to IP addresses in the user defined list
    for line in string:
        line = line.rstrip()
        result = pattern.search(line)
  
        if result:
            Private_IPs.append(line)
    
        else:
            Public_IPs.append(line)
    
    
    """
    # Un-comment this to display the sorted raw Private and Public IP addresses found in the imported list for debugging

    #print("Private IPs")
    #print(Private_IPs)
    #print("Public IPs")
    #print(Public_IPs)

    """
    
    # regex pattern to further filter-sort valid Public IP addresses
    pattern2 =re.compile(r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
    
    # initialized the sorted array values
    valid2 =[]
    invalid2=[]

    # loop through the arrays to filter-sort valid and invalid public ip addresses
    for i in Public_IPs:
        i = i.rstrip()
        result = pattern2.search(i)
        
        if result:
            valid2.append(i)
        else:
            invalid2.append(i)

    # displaying the sorted valid IP addresses prior to running the reverse dns lookup
    print("Valid Public IPs")
    print(valid2, "\n")

    """
    # Un-comment this to display invalid ip addresses for debugging
    print("Invalid IPs")
    print(invalid2)
    """

    # set dataframe to a global value to share the stored value with other functions
    global dataframe
    # set html to a global value to share the stored value with other functions
    global html
    
    # initialize array to store our array of html tables
    html_table_array = []

    # create an array of html tables in html_table_array
    for i in valid2:
        urlReport(i)
        # print(dataframe) is used to print output to the terminal to improve user experience within the terminal.  This can be commented out or removed completely if you do not want to see any output printed in the terminal for each validated entry.
        print(dataframe, "\n")
        html_table_array.append(html)

    # update html variable with our array of html tables stored in html_table_array for use with the outputHTML() function
    html = html_table_array

# ////////////////////////////////// END IMPORT IP LIST



# ////////////////////////////////// START OUTPUT TO HTML

# this function will take either a single html table or an array of html tables, and write them to a CSS styled html file called "report.html"

def outputHTML():

    # save html with css styled boilerplated code up to the first <body> tag to a variable named "header"
    header = """<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Automated VirusTotal Analysis Report | API v3</title>
        <style>
            body {
            font-family: Sans-Serif;
            color: #1d262e;
            }
            h1 {
                font-size: 1.25em;
                margin: 35px 0 0 30px;
            }
            h2 {
                font-size: .75em;
                font-weight:normal;
                margin: 5px 0 15px 30px;
                color: #7d888b;
            }
            h3 {
                font-size: 1em;
                font-weight:normal;
                margin: 0 0 20px 30px;
                color: #7d888b;
            }
            table {
                text-align: left;
                width: 90%;
                border-collapse: collapse;
                border: none;
                padding: 0;
                margin-left: 20px;
                margin-bottom: 40px;
                max-width: 780px;
            }
            th { 
                text-align: left;
                border:none;
                padding: 10px 0 5px 10px;
                margin-left: 10px;
            }
            tr { 
                text-align: left;
                border-bottom: 1px solid #ddd;
                border-top: none;
                border-left: none;
                border-right: none;
                padding-left: 10px;
                margin-left: 0;
            }
            td { 
                border-bottom: none;
                border-top: none;
                border-left: none;
                border-right: none;
                padding-left: 10px;
            }
            tr th {
                padding: 10px 10px 5px 10px;
            }

        </style>
    </head>
    <body>
    <h1 class="reportHeader">Automated VirusTotal Analysis Report</h1>
    <h2>VirusTotal API v3</h2>
    """
    # add report timestamp
    report_timestamp = str("<h3>" + report_time + "</h3>")

    # save html closing </ body> and </ html> tags to a variable named "footer"
    footer = """
        </body>
        </html>
    """
    # create and open the new report.html file
    text_file = open("report.html", "w")
    text_file.write(header)
    text_file.close()

    # open and append report.html with the human-readable date time stored in the report_timestamp variable
    text_file = open("report.html", "a") # append mode
    text_file.write(report_timestamp)
    text_file.close()

    # open and append report.html with a single html table from urlReport(), or as an array of html tables returned by urlReportLst or urlReportIPLst
    text_file = open("report.html", "a") # append mode
    # iterate through the html array and write all the html tables to report.html
    for x in html:
        text_file.write(x)
    text_file.close()

    # open and append report.html with the closing tags stored in the footer variable
    text_file = open("report.html", "a") # append mode
    text_file.write(footer)
    text_file.close()


# ////////////////////////////////// END OUTPUT TO HTML




# ////////////////////////////////// START Read arguments from the command line

args = parser.parse_args()


# Check for --single-entry or -s
if args.single_entry:
    urlReport(args.single_entry)
    print(dataframe)
    outputHTML()
# Check for --ip-list or -i
elif args.ip_list:
    urlReportIPLst(args.ip_list)
    outputHTML()
# Check for --url-list or -u
elif args.url_list:
    urlReportLst(args.url_list)
    outputHTML()
# Check for --version or -V
elif args.version:
    print("VT API v3 IP address and URL analysis 2.0")
# Print usage information if no arguments are provided
else:
    print("usage: vt-ip-url-analysis.py [-h] [-s SINGLE_ENTRY] [-i IP_LIST] [-u URL_LIST] [-V]")

# ////////////////////////////////// END Read arguments from the command line