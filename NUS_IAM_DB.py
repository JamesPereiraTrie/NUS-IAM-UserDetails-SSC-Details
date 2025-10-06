import sqlalchemy
import pandas as pd
import requests
import urllib3
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from ldap3 import Server, Connection, ALL, SUBTREE

LDAP_SERVER = 'ldap://192.168.30.10:389'
USER_DN = 'CN=ssc_binding,OU=Service Accounts,DC=TRIE,DC=local'
PASSWORD = 'P@ssw0rd'
BASE_DN = 'DC=TRIE,DC=local'


SSC_URL = "https://w19ftfssc01.trie.local:8443/ssc"
SSC_KEY = "YjE4NzdmODEtMjVjYS00M2ZmLTkwMTAtNzUyMWU4MTVhMTdl"

# SQLAlchemy setting for dialect and driver
MYSQL_DIALECT = 'mysql'
MYSQL_DRIVER = 'pymysql'

MSSQL_DIALECT = 'mssql'
MSSQL_DRIVER = 'pymssql'

# Fortify SSC database connection settings
SSC_DB_SERVER = '192.168.30.12'

SSC_MYSQL_DB_PORT = '3306'
SSC_MYSQL_DB_NAME = 'db-fortify-ssc'
SSC_MYSQL_DB_USERNAME = 'fortifysscuser'
SSC_MYSQL_DB_PASSWORD = "P%40ssw0rd"

SSC_MSSQL_DB_PORT = '1433'
SSC_MSSQL_DB_NAME = 'SSC_DB'
SSC_MSSQL_DB_USERNAME = 'FortifySSCAdmin'
SSC_MSSQL_DB_PASSWORD = 'Password12345!'

# Build connection string
connStrMYSQL = (
    f"{MYSQL_DIALECT}+{MYSQL_DRIVER}://"
    f"{SSC_MYSQL_DB_USERNAME}:{SSC_MYSQL_DB_PASSWORD}"
    f"@{SSC_DB_SERVER}/{SSC_MYSQL_DB_NAME}"
)

connStrMSSQL = (
    f"{MSSQL_DIALECT}+{MSSQL_DRIVER}://"
    f"{SSC_MSSQL_DB_USERNAME}:{SSC_MSSQL_DB_PASSWORD}"
    f"@{SSC_DB_SERVER}/{SSC_MSSQL_DB_NAME}"
)

# Connect to Fortify SSC database
engine = sqlalchemy.create_engine(connStrMYSQL)
conn = engine.connect()

def get_ldap_group_members(dl_cn, conn):
    # Search for the group by CN
    group_filter = f'(&(objectClass=group)(cn={dl_cn}))'
    conn.search(search_base=BASE_DN, search_filter=group_filter, search_scope=SUBTREE, attributes=['member'])

    if len(conn.entries) == 0:
        print(f"No group found with CN = {dl_cn}")
        return {}

    group_entry = conn.entries[0]
    member_dns = group_entry.member.values if 'member' in group_entry else []

    dl_members = {}  # dictionary keyed by username
    for member_dn in member_dns:
        conn.search(search_base=member_dn, search_filter='(objectClass=person)', attributes=['cn', 'mail'])
        if conn.entries:
            member = conn.entries[0]
            username = member.cn.value
            dl_members[username] = {
                'name': username,
                'email': member.mail.value if 'mail' in member else 'N/A',
                'dl_name': dl_cn
            }
        else:
            # fallback for unknown member
            dl_members[member_dn] = {
                'name': 'Unknown',
                'email': 'N/A',
                'dl_name': dl_cn
            }

    return dl_members

# Get project versions and eApp No (custom attribute) from SSC
def getAllProjectVersions(conn):
    allProjectVersions = {}

    query = """
        SELECT 
    pv.*, 
    p.name AS project_name,
    mv.integervalue AS eAppNo
FROM projectversion pv
LEFT JOIN metavalue mv
    ON mv.projectversion_id = pv.id
    AND mv.metaDef_id = 30
LEFT JOIN project p
    ON p.id = pv.project_id;
    """

    project_df = pd.read_sql(query, conn)

    
    for _, row in project_df.iterrows():
        project_version_id = row['id']  # assuming 'id' is the primary key column
        project_data = row.to_dict()
        allProjectVersions[project_version_id] = project_data
    
    print(allProjectVersions)
    return allProjectVersions

def getAllUsers(conn):
    allFortifyUsers = {}
    allFortifyUserNameToIDForLDAP = {}

    query = """
        SELECT 
    u.id AS "id",
    u.name AS "name",
    u.src AS "type",  -- Shows whether Local or LDAP
    GROUP_CONCAT(pt.name ORDER BY pt.name SEPARATOR ', ') AS "role",
    GROUP_CONCAT(pt.description ORDER BY pt.description SEPARATOR ', ') AS "role_description"
FROM 
    (
        SELECT id, userName AS name, 'Local' AS src 
        FROM fortifyuser
        UNION
        SELECT id, ldapDn AS name, 'LDAP' AS src 
        FROM ldapentity
    ) u
JOIN user_pt upt ON u.id = upt.user_id
JOIN permissiontemplate pt ON upt.pt_id = pt.id
GROUP BY u.id, u.name, u.src
ORDER BY u.name;
    """

    users_df = pd.read_sql(query, conn)

    
    for _, row in users_df.iterrows():
        user_id = row['id'] # assuming 'id' is the primary key column
        

        if row['type'] == "LDAP":
            parts = dict(part.split('=') for part in row['name'].split(',') if '=' in part)

            user_name = parts.get('CN')
            user_extension = parts.get('OU')
            user_LDAP_name = row['name']
        else:
            user_name = row['name']
            user_extension = None
            user_LDAP_name = None

        user_data = {
            "user_id" : row['id'],
            "user_name" : user_name,
            "user_type" : row['type'],
            "user_role" : row['role'],
            "user_extension" : user_extension,
            "user_LDAP_name" : user_LDAP_name,
            "role_description" : row['role_description']
        }
        allFortifyUsers[user_id] = user_data
        if row['type'] == "LDAP":
            allFortifyUserNameToIDForLDAP[user_name] = user_id
    
    return allFortifyUsers, allFortifyUserNameToIDForLDAP



def setAllUsersToApplicationVersions(conn, version_ID, allusers, dl_members, LDAPUsersToID):
    url = f"{SSC_URL}/api/v1/projectVersions/{version_ID}/authEntities"
    headers = {
        "Authorization": f"FortifyToken {SSC_KEY}",
        "Content-Type": "application/json; charset=UTF-8",
        "accept": "application/json"
    }

    response = requests.get(url, headers=headers, verify=False)

    usersInApplication = []

    if response.status_code < 300:
        data_response = response.json()['data']
        if data_response == []:
            print(f"No Users in version {version_ID}")
            return
        else:
            print("*" * 50)
            for user in data_response:
                if user['type'] == "Group":
                    if user['entityName'] in dl_members and dl_members:
                        for ldap_user in dl_members[user['entityName']]:
                            if ldap_user in LDAPUsersToID and LDAPUsersToID:
                                ldap_user_id = LDAPUsersToID[ldap_user]
                                usersInApplication.append(allusers[ldap_user_id])
                            else:
                                print(f"Invalid LDAP User - {ldap_user}")
                    else:
                        print(f"Invalid LDAP Group - {user['entityName']}")
                else:
                    if allusers and user['id'] in allusers:
                        usersInApplication.append(allusers[user['id']])
                    else:
                        print(f"Invalid User - {user['id']} | {user['entityName']}")
        #print(usersInApplication)
        print("#" * 50)
        return usersInApplication
    else:
        print(f"{response.status_code} | ERROR - getAllUserData")
        print(response.text)
        return None
projectVersions = getAllProjectVersions(connStrMYSQL)
allusers, LDAPUsersToID = getAllUsers(connStrMYSQL)

dl_list = ['Fortify Users', 'Admins']
dl_members = {}  # main dictionary keyed by username

server = Server(LDAP_SERVER, get_info=ALL)
ldap_conn = Connection(server, user=USER_DN, password=PASSWORD, auto_bind=True)

for dl in dl_list:
    members = get_ldap_group_members(dl, ldap_conn)
    dl_members[dl] = members  # merge into main dictionary


# for version in projectVersions:
#     print(f"Processing {version}")
#     usersInApplication = setAllUsersToApplicationVersions(conn, version, allusers, dl_members, LDAPUsersToID)
#     print(projectVersions[version])
#     print(usersInApplication)
#     print(f"Completed...")

all_rows = []

for version_id, version_data in projectVersions.items():
    usersInApplication = setAllUsersToApplicationVersions(conn, version_id, allusers, dl_members, LDAPUsersToID)
    
    if usersInApplication:
        for user in usersInApplication:
            # Extract CN and OU if user_name is LDAP format
            cn, ou = None, None
            if user['user_type'] == 'LDAP':
                match = re.search(r'CN=([^,]+),OU=([^,]+)', user['user_LDAP_name'])
                if match:
                    cn, ou = match.groups()
            
            all_rows.append({
                # 'Project Version ID': version_id,
                'Application Name' : version_data.get('project_name'),
                'Version Name': version_data.get('name'),
                'Application ID (eAppNo)' : version_data.get('eAppNo'),
                'Fortify User ID': user['user_id'],
                'Login Account ID': user['user_name'],
                # 'CN': cn,
                'Account Type': ou,
                # 'User Type': user['user_type'],
                'Entitlement Value': user.get('user_role'),
                'Access Description' : user.get('role_description')
                # 'User Extension': user.get('user_extension')
            })

# Convert to DataFrame
df = pd.DataFrame(all_rows)

# Export to Excel
df.to_excel('project_users_v2.xlsx', index=False)

print("Exported all users to project_users.xlsx")


ldap_conn.unbind()
conn.close()
engine.dispose()
