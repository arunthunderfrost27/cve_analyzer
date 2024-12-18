Clone the Repository using [https://github.com/arunthunderfrost27/cve_analyzer.git]
(https://github.com/arunthunderfrost27/cve_analyzer.git)

To run the Application

cd backend

python process.py -> select any port =>To start the Flask App and the homepage.

python web_sync.py => To fetch the data from web json url and 
compare every record with the existing database records to find the unique and replace.

python autosync.py => To run the manual synchronization and initiate the windows task scheduler to autoupdate.

python file_sync.py => To run the database updation based on the downloaded json file and
compare every record with the existing database records to find the unique and replace.

python database.py => To drop all the collections and replace the database

sample input json file: https://services.nvd.nist.gov/rest/json/cves/2.0 

Concepts:

National Vulnerability Database=>
The NVD is the U.S. government repository of standards based vulnerability management data represented using the Security Content Automation Protocol (SCAP).
This data enables automation of vulnerability management, security measurement, and compliance.

Common Vulnerabilities and Exposures=>
System that assigns unique identifiers to publicly known security vulnerabilities.Each CVE entry includes a description, impact, and references. 
It standardizes vulnerability tracking to help organizations address security risks effectively
This Application analyses the sample records of cve database

API Endpoints Descriptions:

POST /load_cve_data =>To load the cve data into mongodb.[database.py]

GET /api/cves/{cveId} =>To fetch the details of a specific CVE by its ID.

GET /api/cves =>To fetch list of cves at certain limit to manage pagination.

MongoDB Schema:

cve_metadata =>stores metadata related to each CVE, such as the CVE ID, source identifier,publication and modification dates and vulnerability status.

descriptions =>stores descriptions of the CVEs, including language and description text.

metrics =>stores the CVSS metrics for each CVE, including base score, vector string, access vector, complexity, and other impacts.

cpe =>stores Common Platform Enumeration (CPE) information for each CVE entry, including the vulnerable CPE matches and their criteria.

Auto-Synchronize :

win32com.client triggers the autoupdate to load the unique json records into mongodb database scheduled at every 2.00 AM.

Well defined unit test cases for the functionalities :
To check the test cases modify the json file in data folder and run python file_sync.py

1.Case 1 -> Fetching the cve details by cve id

Input : click on cve-id : CVE-2000-0302 row -> GET /api/cves/CVE-2000-0302 -> 
To fetch the details of cve record based on cve id

Expected Output : make reference from sample-detailpage.png attached in the git repository

2.Case 2 -> Updating the identifier in existing cve record

input :

Cve Id : CVE-1999-1485
Identifier : cve@mitre.org
Published Date : 31 May 1999
Last Modified Date : 20 Nov 2024
Status : Modified

expected output :

MongoDB initiated
Processed 2000 CVE Entries
updated 1 entries of the database


Cve Id : CVE-1999-1485
Identifier : cve2@mitre.org
Published Date : 31 May 1999
Last Modified Date : 18 Dec 2024[Updated date]
Status : Modified


3.Case 3 -> deleting a cve record in json file

Deleteing this record->
Cve Id : CVE-2000-0296
Identifier : cve@mitre.org
Published Date : 31 Mar 2000
Last Modified Date : 20 Nov 2024
Status : Modified

Expected output : 

MongoDB initiated
Processed 1999 CVE Entries[excluding the deleted record]
i entries has been deleted

4.Case 4 -> Adding a cve record in json file

Cve Id : CVE-2000-0298
Identifier : cve@mitre.org
Published Date : 31 Mar 2000
Last Modified Date : 15 Dec 2024[Updated date]
Status : Modified

Expected output : 

MongoDB initiated
Loaded 2001 CVE Entries into mongodb[including the deleted record]











