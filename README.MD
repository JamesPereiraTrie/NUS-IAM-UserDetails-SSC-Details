### Fortify SSC Application User Mapper

## Description
This Python script extracts **Fortify SSC applications** and their associated users from the Fortify database.  
It also retrieves user information from an **LDAP server**, including users that are part of groups, to build a complete mapping.  

The script then loops through all applications in Fortify SSC and calls the SSC API for each application to determine which users have access.

**SSC API Endpoint Used:**  
{SSC_URL}/api/v1/projectVersions/{version_ID}/authEntities

## Dependency Requirements
The script requires the following Python libraries:

sqlalchemy
pandas
requests
urllib3

pip install -r requirements.txt

## Credentials Needed

# Fortify
SSC API TOKEN (Automation Token)

# Fortify SSC Database
SSC Database Server 
SSC MySQL/MsSQL Database Port
SSC MySQL/MsSQL Database Name
SSC MySQL/MsSQL Database User-Username
SSC MySQL/MsSQL Database User-Password

# LDAP Server
LDAP Server
Bind User DN (i.e 'CN=ssc_binding,OU=Service Accounts,DC=TRIE,DC=local')
Bind User Password
Base DN


## Summary of Workflow

1. Connect to Fortify SSC database and retrieve project versions.

2. Connect to LDAP server to retrieve users, including group memberships.

3. Loop through each project version and call the SSC API endpoint to get authorized users.

4. Map users to applications and optionally export results to Excel for reporting.


