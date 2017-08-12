#!/usr/bin/python

########################################################################################################
# Name: Nessus Report downloader
# Author: Nikhil Raj ( nikhilraj149@gmail.com )
#
# Version: 1.0
# Last Updated: 13 Aug 2017
#
# Description:  A python script for automating the download of nessus reports in multiple formats.
#
# Usage: 	$ python nessus_report_downloader.py -i <nessus_server_ip> -u <nessus_user> -p <nessus_passwd>
#
# Requirements: This script requires below two libraries which may not be present by default in your
#		python installation:
#
#		1) Requests - Required for sending HTTP requests
#		2) PrettyTable (Optional) - for formatting data in tabular fashion on terminal
#
#########################################################################################################

import requests
import json
import argparse
import time
from datetime import datetime

try:
    from prettytable import PrettyTable1
except ImportError:
    print "[-] Unable to load PrettyTable library, will print data in generic format"
    HAS_PRETTYTABLE = False
else:
    HAS_PRETTYTABLE = True

# Disable ssl error warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

SLEEP_TIME=1.0

# Send HTTP GET request
def sendGetRequest(url, headers):
    try:
        r = requests.get(url, verify=False, headers=headers)
        return r
    except requests.exceptions.ConnectionError:
        print "[-] Failed to establish connection"
        exit(-1)


# Send HTTP POST request
def sendPostRequest(url, json_data={}, headers={}):
    try:
        r = requests.post(url, verify=False, headers=headers, json=json_data)
        return r
    except requests.exceptions.ConnectionError:
        print "[-] Failed to establish connection"
        exit(-1)

# Send HTTP DELETE request
def sendDeleteRequest(url, json_data={}, headers={}):
    try:
        r = requests.delete(url, verify=False, headers=headers, json=json_data)
        return r
    except requests.exceptions.ConnectionError:
        print "[-] Failed to establish connection"
        exit(-1)

# Print message on stdout
def printMessage(msg, flag=1):
    if flag == 1:
        print "[+] " + msg
    elif flag == 0:
        print "[-] " + msg
    elif flag == 2:
        print "[*] " + msg
    else:
        print msg


# Check response code for an HTTP Response and print req message
def checkStatus(resp, status_msg, error_msg):
    if resp.status_code == 200:
        printMessage(status_msg, 1)
        return True
    else:
        printMessage(error_msg, 0)
        return False


# Print data ( list of dictionary ) in tabular format
def printTable(data, table_headers):
    tab = PrettyTable(table_headers)

    for row in data:
        l = list()
        for header in table_headers:
            if "date" in header:
                l.append(datetime.fromtimestamp(int(row[header])).strftime('%Y-%m-%d %H:%M:%S'))
            else:
                l.append(str(row[header]))
        tab.add_row(l)
    print tab


def printScanData(scan_data):
    # Processing folder info
    folder_info = dict()
    for folder in scan_data["folders"]:
        folder_info[folder["id"]] = folder["name"]

    if HAS_PRETTYTABLE:
        printTable(scan_data["scans"], ["id", "name", "folder_id", "status", "creation_date", "last_modification_date"])
    else:
        # print scan header
        print '\t %-10s  %-20s  %-20s  %-40s %-20s %-20s'  %("Scan Id", "Folder Name (id)", "Scan status","Scan Name","creation_date", "last_modification_date")
        print '\t %-10s  %-20s  %-20s  %-40s %-20s %-20s'  %("-------", "---------------", "------------", "-----------------","-------------------", "--------------------")
        for scan in scan_data["scans"]:
            print '\t %-10s  %-20s  %-20s  %-40s %-20s %-20s' %(str(scan["id"]),folder_info[scan["folder_id"]] + ' (' + str(
                scan["folder_id"]) + ') ', scan["status"], scan["name"],datetime.fromtimestamp(int(scan["creation_date"])).strftime('%Y-%m-%d %H:%M:%S'),datetime.fromtimestamp(int(scan["last_modification_date"])).strftime('%Y-%m-%d %H:%M:%S'))

        print '\n'

# Verify user specified folder Id
def verifyScanId(scan_data, ui_scan_id):
    master_scan_id_list = list()
    valid_scan_list = list()

    for scan in scan_data["scans"]:
        master_scan_id_list.append(scan["id"])

    if ui_scan_id == "all":
        return master_scan_id_list

    for scan in ui_scan_id.split(","):
        if int(scan) in master_scan_id_list:
            valid_scan_list.append(scan)
        else:
            printMessage("Omitting invalid Scan ID: " + scan, 0)

    return valid_scan_list


# Verify user specified folder id and extract all scans id(s) associated to it
def verifyFolderId(scan_data, ui_folder_id):
    master_folder_id_list = list()
    valid_folder_id_list = list()
    scan_id_list = list()

    for folder in scan_data["folders"]:
        master_folder_id_list.append(folder["id"])

    for folder_id in ui_folder_id.split(","):
        if int(folder_id) in master_folder_id_list:
            valid_folder_id_list.append(folder_id)
        else:
            printMessage("Omitting invalid folder ID: " + folder_id, 0)

    for scan in scan_data["scans"]:
        for folder_id in valid_folder_id_list:
            if int(scan["folder_id"]) == int(folder_id):
                scan_id_list.append(scan["id"])

    return scan_id_list


def getFormatAndChapterList(nessus_format_list, chapter_list, db_pass):
    data=list()

    for nessus_format in nessus_format_list:
        if nessus_format == "0":
            data.append({'format': 'nessus', 'chapters': ''})
        if nessus_format == "1":
            for chapter in chapter_list:
                if chapter == "0":
                    data.append({'format': 'pdf', 'chapters': 'vuln_hosts_summary'})
                if chapter == "1":
                    data.append({'format': 'pdf', 'chapters': 'vuln_by_host'})
                if chapter == "2":
                    data.append({'format': 'pdf', 'chapters': 'vuln_by_plugin'})
                if chapter == "3":
                    data.append({'format': 'pdf', 'chapters': 'compliance_exec'})
                if chapter == "4":
                    data.append({'format': 'pdf', 'chapters': 'compliance'})
                if chapter == "5":
                    data.append({'format': 'pdf', 'chapters': 'remediations'})
        if nessus_format == "2":
            for chapter in chapter_list:
                if chapter == "0":
                    data.append({'format': 'html', 'chapters': 'vuln_hosts_summary'})
                if chapter == "1":
                    data.append({'format': 'html', 'chapters': 'vuln_by_host'})
                if chapter == "2":
                    data.append({'format': 'html', 'chapters': 'vuln_by_plugin'})
                if chapter == "3":
                    data.append({'format': 'html', 'chapters': 'compliance_exec'})
                if chapter == "4":
                    data.append({'format': 'html', 'chapters': 'compliance'})
                if chapter == "5":
                    data.append({'format': 'html', 'chapters': 'remediations'})
        if nessus_format == "3":
            data.append({'format': 'csv', 'chapters': ''})
        if nessus_format == "4":
            data.append({'format': 'db', 'chapters': '', 'password' : db_pass})

    return data

def downloadNessusReport(base_url, token, scan_id_list, json_user_data):
    for scan_id in scan_id_list:

        printMessage("Format: {0} | Chapter: {1}".format(json_user_data["format"], json_user_data["chapters"]))
        printMessage("Initiating download request for scan id: " + str(scan_id), 1)

        token_header={'X-Cookie': 'token=' + token['token']}

        # Initiate download request for given scan id
        url = base_url + "/scans/{0}/export".format(str(scan_id))
        resp = sendPostRequest(url, json_data=json_user_data,headers=token_header)
        file_token = json.loads(resp.text)

        # Check if file is ready for download
        url = base_url + "/scans/{0}/export/{1}/status".format(str(scan_id),str(file_token["file"]))
        resp2 = sendGetRequest(url,headers=token_header)
        while json.loads(resp2.text)["status"] == "loading":
            printMessage("Report is not ready yet, waiting for {0} seconds".format(SLEEP_TIME),0)
            time.sleep(SLEEP_TIME)
            resp2 = sendGetRequest(url, headers=token_header)

        # If nessus report is ready for download, then write the response in external file
        url= base_url + "/scans/exports/{0}/download".format(str(file_token["token"]))
        if json.loads(resp2.text)["status"] == "ready":
            printMessage("Download link is available now", 1)
            resp3 = sendGetRequest(url,headers=token_header)

            if checkStatus(resp3, "Started downloading the nessus report",
                           "Unable to download scan: " + str(scan_id)):
                filename = resp3.headers["Content-Disposition"].split('"')[1]
                try:
                    nessus_file = open(filename, "w")
                    nessus_file.write(resp3.text)
                    nessus_file.close()
                    printMessage("Report was saved in " + filename, 1)
                    printMessage("\n", 99)
                except IOError:
                    printMessage("Error occurred while writing to file : " + filename, 0)
                except UnicodeEncodeError:
                    # Append the chapter type in file name
                    filename2=filename.split(".")[0]+'_'+json_user_data["chapters"]+'.'+filename.split(".")[-1]
                    nessus_file = open(filename2, "wb")
                    nessus_file.write(resp3.content)
                    nessus_file.close()
                    printMessage("Report was saved in " + filename2, 1)
                    printMessage("\n", 99)


def main():

    # Parsing command line options
    parser = argparse.ArgumentParser(description="A python script for automating the report download from nessus server",
                                     epilog="Report bugs at nikhilraj149@gmail.com",
                                     prog='python nessus_report_downloader.py', usage='%(prog)s -i <127.0.0.1> -u <nessus_user> -p <nessus_pass> [OPTIONS]... ')
    parser.add_argument("-i", "--server", help="IP[:PORT] of nessus server", required=True)
    parser.add_argument("-u", "--user", help="username of nessus server", required=True)
    parser.add_argument("-p", "--passwd", help="password of nessus server", required=True)
    parser.add_argument("-s", "--scan-id", help="use comma separated list of scan id(s) or 'all' ")
    parser.add_argument("-d", "--folder-id", help="use comma separated list of folder id(s)")
    parser.add_argument("-f", "--format", help="use comma separated list of report format; [0]-nessus (Default), [1]-pdf, [2]-html, [3]-csv, [4]-nessus-db",default="0")
    parser.add_argument("-c", "--chapter", help="use comma separated list of chapters; [0]-vuln_hosts_summary, [1]-vuln_by_host (Default), "
                                                "[2]-vuln_by_plugin, [3]-compliance_exec, [4]-compliance, [5]-remediations",default="1")
    parser.add_argument("--db-pass", help="password for encrypting nessus-db file(s), if none specified use 'nessus'",default="nessus")
    args = parser.parse_args()

    # Nessus server url
    if ":" in args.server:
        ip = args.server.split(":")[0]
        port = args.server.split(":")[1]
    else:
        ip = args.server
        port = "8834"

    base_url = "https://" + ip + ":" + port

    # Login credentials
    creds = {'username': args.user, 'password': args.passwd}


    # Checking connection to nessus server
    resp = sendGetRequest(base_url, "")
    if checkStatus(resp, "Connected to nessus server", "Unable to connect to server at " + str(ip)):

        # Login to nessus server and get session token
        resp = sendPostRequest(base_url + "/session", creds)
        if checkStatus(resp, "Login successful", "Invalid Login credentials"):
            token = json.loads(resp.text)
            # print token["token"]

            # Fetching nessus scan report list
            resp = sendGetRequest(base_url + "/scans", headers={'X-Cookie': 'token=' + token['token']})
            if checkStatus(resp, "Fetching scan reports\n", "Unable to fetch nessus scan"):
                scan_data = json.loads(resp.text)

                # If no download option specified (-s or -d) then print scan info
                if not args.scan_id and not args.folder_id:
                    printScanData(scan_data)

                # Download the report if scan_id or folder_id supplied via -s or -d option
                else:
                    if args.scan_id:
                        scan_id_list = verifyScanId(scan_data, args.scan_id)
                    elif args.folder_id:
                        scan_id_list = verifyFolderId(scan_data, args.folder_id)

                    printMessage("Identified " + str(len(scan_id_list)) + " scan(s) for download\n", 2)

                    # Choose default values if not supplied via std input
                    if not args.format:
                        printMessage("Missing -f option, using default [0]-nessus format\n",0)
                    if not args.chapter and (("1" in args.format) or ("2" in args.format)):
                        printMessage("Missing -g option, If required vuln_by_host will be default chapter\n", 0)
                    if not args.db_pass and "4" in args.format:
                        printMessage("Missing --db-pass option, using default db password: 'nessus' \n", 0)

                    # Create a list of format and chapters for report creation
                    format_specification = getFormatAndChapterList(args.format, args.chapter, args.db_pass)
                    for report_format in format_specification:
                        downloadNessusReport(base_url, token, scan_id_list, json_user_data=report_format)

            # Logout
            resp = sendDeleteRequest(base_url+"/session",headers={'X-Cookie': 'token=' + token['token']})
            checkStatus(resp, "Successfully logged out user session\n", "Unable to logout the current active session")

    printMessage("Thanks, See you again!")

if __name__ == '__main__':
    main()