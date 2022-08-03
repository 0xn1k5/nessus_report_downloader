# nessus_report_downloader


 **Name** : **Nessus Report downloader**

 **Author** : **Nikhil Raj ( Twitter: 0xn1k5 | Mail: nikhilraj149[@]gmail.com )**

 **Version: 1.0**
 
 **Last Updated** : 13 Aug 2017

 **Description**:  
 
    A python script for automating the download of nessus reports in multiple formats.

 **Usage**:
 
 1) Display help

    $ python nessus_report_downloader.py -h 
    
    Output:
    
        usage: python nessus_report_downloader.py -i <127.0.0.1> -u <nessus_user> -p <nessus_pass> [OPTIONS]... 
    
        A python script for automating the report download from nessus server
        
        optional arguments:
          -h, --help            show this help message and exit
          -i SERVER, --server SERVER
                                IP[:PORT] of nessus server
          -u USER, --user USER  username of nessus server
          -p PASSWD, --passwd PASSWD
                                password of nessus server
          -s SCAN_ID, --scan-id SCAN_ID
                                use comma separated list of scan id(s) or 'all'
          -d FOLDER_ID, --folder-id FOLDER_ID
                                use comma separated list of folder id(s)
          -f FORMAT, --format FORMAT
                                use comma separated list of report format; [0]-nessus
                                (Default), [1]-pdf, [2]-html, [3]-csv, [4]-nessus-db
          -c CHAPTER, --chapter CHAPTER
                                use comma separated list of chapters;
                                [0]-vuln_hosts_summary, [1]-vuln_by_host (Default),
                                [2]-vuln_by_plugin, [3]-compliance_exec,
                                [4]-compliance, [5]-remediations
          --db-pass DB_PASS     password for encrypting nessus-db file(s), if none
                                specified use 'nessus'
        
        Report bugs at nikhilraj149@gmail.com
    
 2) Display nessus scan summary table having scan_id, name and folder_id

    $ python nessus_report_downloader.py -i <nessus_server_ip> -u <nessus_user> -p <nessus_passwd>
    
    $ python nessus_report_downloader.py -i 127.0.0.1 -u nessus -p pass@123
    
    Output:
        
        +----+------------------------------+-----------+-----------+---------------------+------------------------+
        | id |             name             | folder_id |   status  |    creation_date    | last_modification_date |
        +----+------------------------------+-----------+-----------+---------------------+------------------------+
        | 12 | P@wn3d!! - Home network scan |     3     | completed | 2017-08-05 22:13:17 |  2017-08-05 22:16:38   |
        | 23 |        Metasploitable        |     3     | completed | 2017-08-03 21:45:23 |  2017-08-03 21:53:19   |
        | 19 |          Test-win7           |     3     | completed | 2017-07-31 01:13:25 |  2017-07-31 01:13:45   |
        | 14 |    Win7 Test -Post Wnycry    |     3     | completed | 2017-07-23 18:40:30 |  2017-07-23 18:40:46   |
        | 11 |          Win7 Test           |     3     | completed | 2017-07-23 13:35:18 |  2017-07-23 13:35:36   |
        +----+------------------------------+-----------+-----------+---------------------+------------------------+


    
 3) Download nessus report (Optional parameter description):

    
    Scan Id (-s):
    
        - List of comma seperated scan id for download 
        $ python nessus_report_downloader.py -i <nessus_server_ip> -u <nessus_user> -p <nessus_passwd> -s <11,12,14>
    
    Folder ID (-d):
    
        - List of comma seperated folder id for downloading all the scans inside it
        $ python nessus_report_downloader.py -i <nessus_server_ip> -u <nessus_user> -p <nessus_passwd> -d <3>
    
    Output Format (-f): 
    
        0 -     Nessus XML data (*.nessus) [Default]
        1 -     PDF Format 
        2 -     HTML Format
        3 -     CSV Format
        4 -     Nessus encrypted database password
    
    Chapter (-c) : ( Applicable only when downloading in PDF or HTML format)
    
        0 -     vuln_hosts_summary 
        1 -     vuln_by_host        [Default]
        2 -     vuln_by_plugin
        3 -     compliance_exec
        4 -     compliance
        5 -     remediations
                        
    Nessus Database password ( --db-pass)
        
        - password required for encrypting nessus-db files 
        - If not specified, Default password = "nessus"                    
                        
    Example:
    
    1) Download nessus report for scan_id 11, 12 and 14 in default *.nessus format
         
        $ python nessus_report_downloader.py -i 127.0.0.1 -u nessus -p pass@123 -s 11,12,14 -f 0
    
    3) Download nessus report for scan_id 11  in nessus database format using password "secret_pass"
    
        $ python nessus_report_downloader.py -i 127.0.0.1 -u nessus -p pass@123 -s 11 -f 4 --db-pass secret_pass
    
    4) Download nessus report for scan_id 11 and 12 in pdf and html format and group by host (vuln_by_host)
    
        $ python nessus_report_downloader.py -i 127.0.0.1 -u nessus -p pass@123 -s 11,12,14 -f 1,2 -c 1
    
    5) Download nessus report for scan_id 11 and 12 in csv and html format and group by vulnerability (vuln_by_plugin)
    
        $ python nessus_report_downloader.py -i 127.0.0.1 -u nessus -p pass@123 -s 11,12 -f 2,3 -c 2
    
    6) Download all nessus report in default *.nessus format\
    
        $ python nessus_report_downloader.py -i 127.0.0.1 -u nessus -p pass@123 -s all -f 0 
        
    7) Download all nessus report in pdf and html format and group by vulnerability (vuln_by_plugin)
    
        $ python nessus_report_downloader.py -i 127.0.0.1 -u nessus -p pass@123 -s all -f 1,2 -c 2
        
    8) Download all nessus report in folder_id 3 in default *.nessus format
     
          $ python nessus_report_downloader.py -i 127.0.0.1 -u nessus -p pass@123 -d 3 -f 0
    
    
                        
                        
                   
          



