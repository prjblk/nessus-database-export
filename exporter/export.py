#!/usr/bin/env python3
import configparser
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import pymysql.cursors
import os
import json
import re

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Read configuration
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'config.ini'))

nessus_hostname = config.get('nessus','hostname')
nessus_port = config.get('nessus','port')
access_key = 'accessKey=' + config.get('nessus','access_key') + ';'
secret_key = 'secretKey=' + config.get('nessus','secret_key') + ';'
base = 'https://{hostname}:{port}'.format(hostname=nessus_hostname, port=nessus_port)
trash = config.getboolean('nessus','trash')
debug = config.getboolean('nessus', 'debug', fallback=False)
compliance = config.getboolean('nessus', 'compliance', fallback=False)

db_hostname = config.get('mysql','hostname')
username = config.get('mysql','username')
password = config.get('mysql','password')
database = config.get('mysql','database')

# Nessus endpoints
FOLDERS = '/folders'
SCANS = '/scans'

SCAN_ID = SCANS + '/{scan_id}'
HOST_ID = SCAN_ID + '/hosts/{host_id}'
PLUGIN_ID = HOST_ID + '/plugins/{plugin_id}'
COMPLIANCE_ID = HOST_ID + '/compliance/{compliance_id}'

SCAN_RUN = SCAN_ID + '?history_id={history_id}'
HOST_VULN = HOST_ID + '?history_id={history_id}'
PLUGIN_OUTPUT = PLUGIN_ID + '?history_id={history_id}'
COMPLIANCE_OUTPUT = COMPLIANCE_ID + '?history_id={history_id}'

# Database connection
connection = pymysql.connect(host=db_hostname,
                             user=username,
                             password=password,
                             db=database,
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor,
                             autocommit=False)

# Get API token for compliance requests
def get_api_token():
    if not compliance:
        return None
        
    url = base + '/nessus6.js'
    headers = {'X-ApiKeys': access_key + secret_key}
    response = requests.get(url=url, headers=headers, verify=False)
    
    if response.status_code == 200:
        if debug:
            print(f"[DEBUG] nessus6.js response:")
            print(response.text[:500])  # Print first 500 chars to see the structure
            
        # Try different regex patterns
        patterns = [
            r'getApiToken\(\),value:function\(\){return"([^"]+)"',
            r'getApiToken\(\){return"([^"]+)"',
            r'getApiToken:function\(\){return"([^"]+)"',
            r'getApiToken.*?return"([^"]+)"'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response.text)
            if match:
                token = match.group(1)
                if debug:
                    print(f"[DEBUG] Found API token: {token}")
                return token
                
    if debug:
        print(f"[DEBUG] No API token found in response")
        print(f"[DEBUG] Response status code: {response.status_code}")
    return None

api_token = get_api_token()
if debug:
    print(f"[DEBUG] Initial API token: {api_token}")

# ---Functions---
# Nessus API functions
def request(url):
    url = base + url
    headers = {'X-ApiKeys': access_key + secret_key}
    
    # Add API token for compliance requests
    if compliance and api_token and 'compliance' in url:
        if debug:
            print(f"[DEBUG] Adding API token for compliance request: {url}")
        headers['X-API-Token'] = api_token
        
    response = requests.get(url=url, headers=headers, verify=False)
    if debug:
        print(f"[DEBUG] Requesting URL: {url}")
        print(f"[DEBUG] Headers: {headers}")
        print(f"[DEBUG] Response status: {response.status_code}")
    return response.json()

def get_folders():
    return request(FOLDERS)

def get_scans():
    return request(SCANS)

def get_scan(scan_id):
    return request(SCAN_ID.format(scan_id=scan_id))

def get_scan_run(scan_id, history_id):
    return request(SCAN_RUN.format(scan_id=scan_id, history_id=history_id))

def get_host_vuln(scan_id, host_id, history_id):
    return request(HOST_VULN.format(scan_id=scan_id, host_id=host_id, history_id=history_id))

def get_compliance_output(scan_id, host_id, compliance_id, history_id):
    return request(COMPLIANCE_OUTPUT.format(scan_id=scan_id, host_id=host_id, compliance_id=compliance_id, history_id=history_id))

def get_plugin_output(scan_id, host_id, plugin_id, history_id):
    return request(PLUGIN_OUTPUT.format(scan_id=scan_id, host_id=host_id, plugin_id=plugin_id, history_id=history_id))

# Nessus export functions
def update_folders():
    folders = get_folders()
    with connection.cursor() as cursor:
        # Upsert folders
        for folder in folders['folders']:
            if debug:
                print(f"\n[DEBUG] Inserting/Updating folder:")
                print(json.dumps(folder, indent=2))
            sql = "INSERT INTO `folder` (`folder_id`, `type`, `name`)\
                    VALUES (%s, %s, %s)\
                    ON DUPLICATE KEY UPDATE type=%s, name=%s"
            cursor.execute(sql, (folder['id'], folder['type'], folder['name'], folder['type'], folder['name']))
    connection.commit()

def update_plugin(plugin, cursor):
    if debug:
        print(f"\n[DEBUG] Processing plugin:")
        print(json.dumps(plugin, indent=2))
    
    # Check existing plugin_id in plugin DB
    sql = "SELECT `plugin_id`, `mod_date` FROM `plugin` WHERE `plugin_id` = %s"
    cursor.execute(sql, (plugin['pluginid']))
    result = cursor.fetchone()

    # Split references array into string delimited by new line
    reference = None
    if plugin['pluginattributes'].get('see_also', None) != None:
        reference = '\n'.join(plugin['pluginattributes'].get('see_also', None))

    if result != None:
        if result['mod_date'] != plugin['pluginattributes']['plugin_information'].get('plugin_modification_date', None):
            # New version of plugin exists, build update query
            sql = "UPDATE `plugin` \
            SET `severity` = %s, `name` = %s, `family` = %s, `synopsis` = %s, `description` = %s, `solution` = %s,\
            `cvss_base_score` = %s, `cvss3_base_score` = %s, `cvss_vector` = %s, `cvss3_vector` = %s, `ref` = %s, `pub_date` = %s, `mod_date` = %s, `policy_value` = %s\
            WHERE `plugin_id` = %s"

            cursor.execute(sql, (
            plugin['severity'], 
            plugin['pluginname'], 
            plugin.get('pluginfamily', None) or plugin.get('plugin_family', None),
            plugin['pluginattributes'].get('synopsis', None),
            plugin['pluginattributes'].get('description', None),
            plugin['pluginattributes'].get('solution', None),
            plugin['pluginattributes'].get('risk_information', {}).get('cvss_base_score', None),
            plugin['pluginattributes'].get('risk_information', {}).get('cvss3_base_score', None),
            plugin['pluginattributes'].get('risk_information', {}).get('cvss_vector', None),
            plugin['pluginattributes'].get('risk_information', {}).get('cvss3_vector', None),
            reference,
            plugin['pluginattributes'].get('plugin_information', {}).get('plugin_publication_date', None),
            plugin['pluginattributes'].get('plugin_information', {}).get('plugin_modification_date', None),
            plugin['pluginattributes'].get('policy_value', None),
            plugin['pluginid']
            ))

        else:
            # Looks like the plugin version is the same skipping
            return None

    else:
        # Doesn't exist, build insert query
        sql = "INSERT INTO `plugin` (`plugin_id`, `severity`, `name`, `family`, `synopsis`, `description`, `solution`,\
            `cvss_base_score`, `cvss3_base_score`, `cvss_vector`, `cvss3_vector`, `ref`, `pub_date`, `mod_date`, `policy_value`)\
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"

        cursor.execute(sql, (
        plugin['pluginid'], 
        plugin['severity'], 
        plugin['pluginname'], 
        plugin.get('pluginfamily', None) or plugin.get('plugin_family', None),
        plugin['pluginattributes'].get('synopsis', None),
        plugin['pluginattributes'].get('description', None),
        plugin['pluginattributes'].get('solution', None),
        plugin['pluginattributes'].get('risk_information', {}).get('cvss_base_score', None),
        plugin['pluginattributes'].get('risk_information', {}).get('cvss3_base_score', None),
        plugin['pluginattributes'].get('risk_information', {}).get('cvss_vector', None),
        plugin['pluginattributes'].get('risk_information', {}).get('cvss3_vector', None),
        reference,
        plugin['pluginattributes'].get('plugin_information', {}).get('plugin_publication_date', None),
        plugin['pluginattributes'].get('plugin_information', {}).get('plugin_modification_date', None),
        plugin['pluginattributes'].get('policy_value', None)
        ))

def insert_vuln_output(vuln_output, host_vuln_id, cursor):
    for output in vuln_output:
        for port in output['ports'].keys():
            sql = "INSERT INTO `vuln_output` (`host_vuln_id`, `port`, `output`)\
                    VALUES (%s, %s, %s)"
            cursor.execute(sql, (host_vuln_id, port, output['plugin_output']))

def insert_compliance_output(compliance_output, compliance_id, cursor):
    for output in compliance_output:
        sql = "INSERT INTO `compliance_output` (`compliance_id`, `output`)\
                VALUES (%s, %s)"
        cursor.execute(sql, (compliance_id, output['plugin_output']))

def insert_host_vuln(scan_id, host_id, plugin_id, history_id, cursor):
    # Need to insert plugin first to have FK relationship
    # Get vuln output which includes plugin info
    vuln_output = get_plugin_output(scan_id, host_id, plugin_id, history_id)
    if debug:
        print(f"\n[DEBUG] Processing host vulnerability:")
        print(f"Scan ID: {scan_id}")
        print(f"Host ID: {host_id}")
        print(f"Plugin ID: {plugin_id}")
        print(f"History ID: {history_id}")
        print("Vuln Output:")
        print(json.dumps(vuln_output, indent=2))
    
    update_plugin(vuln_output['info']['plugindescription'], cursor)

    # Insert host vuln
    sql = "INSERT INTO `host_vuln` (`nessus_host_id`, `scan_run_id`, `plugin_id`)\
            VALUES (%s, %s, %s)"
    cursor.execute(sql, (host_id, history_id, plugin_id))

    # Finally insert vuln output
    insert_vuln_output(vuln_output['outputs'], cursor.lastrowid, cursor)

def insert_compliance(scan_id, host_id, compliance_id, status, history_id, cursor):
    compliance_output = get_compliance_output(scan_id, host_id, compliance_id, history_id)
    if debug:
        print(f"\n[DEBUG] Processing compliance:")
        print(json.dumps(compliance_output, indent=2))

    update_plugin(compliance_output['info']['plugindescription'], cursor)
    # Insert compliance check
    sql = "INSERT INTO `compliance` (`nessus_host_id`, `scan_run_id`, `plugin_id`, `status`)\
            VALUES (%s, %s, %s, %s)"
    cursor.execute(sql, (host_id, history_id, compliance_id, status))

    # Finally insert compliance output
    insert_compliance_output(compliance_output['outputs'], cursor.lastrowid, cursor)

def insert_host(scan_id, host_id, history_id, cursor):
    # Get host vulnerabilities for a scan run
    host = get_host_vuln(scan_id, host_id, history_id) 
    
    if debug:
        print(f"\n[DEBUG] Processing host:")
        print(f"Scan ID: {scan_id}")
        print(f"Host ID: {host_id}")
        print(f"History ID: {history_id}")
        print("Host Data:")
        print(json.dumps(host, indent=2))

    # Count number of vulns of each severity for this host in this scan run
    # 0 is informational, 4 is critical
    sev_count = [0] * 5
    if 'vulnerabilities' in host:
        for vuln in host['vulnerabilities']:
            if vuln['severity'] != None:
                sev_count[vuln['severity']] += vuln['count']
    
    # Count compliance checks
    # 1 is passed, 2 is warning, 3 is fail
    comp_count = [0] * 4  # Index 0 unused, 1=passed, 2=warning, 3=fail
    if compliance and 'compliance' in host:
        for comp in host['compliance']:
            if comp['severity'] != None:
                comp_count[comp['severity']] += comp['count']

    # Insert host information
    sql = "INSERT INTO `host` (`nessus_host_id`, `scan_run_id`, `scan_id`, `host_ip`, `host_fqdn`, `host_start`, `host_end`, `os`,\
        `critical_count`, `high_count`, `medium_count`, `low_count`, `info_count`,\
        `comp_pass_count`, `comp_warning_count`, `comp_fail_count`)\
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"

    cursor.execute(sql, (
        host_id, 
        history_id, 
        scan_id, 
        host['info']['host-ip'], 
        host['info'].get('host-fqdn', None), 
        host['info'].get('host_start', None), 
        host['info'].get('host_end', None), 
        host['info'].get('operating-system', None),
        sev_count[4], sev_count[3], sev_count[2], sev_count[1], sev_count[0],
        comp_count[1], comp_count[2], comp_count[3]
        ))

    # Insert host vulnerabilities
    if 'vulnerabilities' in host:
        for vuln in host['vulnerabilities']:
            insert_host_vuln(scan_id, host_id, vuln['plugin_id'], history_id, cursor)

    # Insert compliance checks
    if compliance and 'compliance' in host:
        for comp in host['compliance']:
            insert_compliance(scan_id, host_id, comp['plugin_id'], comp['severity'], history_id, cursor)

def insert_scan_run(scan_id, history_id):
    # Get scan runs for a scan
    scan_run = get_scan_run(scan_id, history_id)
    
    if debug:
        print(f"\n[DEBUG] Processing scan run:")
        print(f"Scan ID: {scan_id}")
        print(f"History ID: {history_id}")
        print("Scan Run Data:")
        print(json.dumps(scan_run, indent=2))

    # Count number of vulns of each severity for this scan run
    # 0 is informational, 4 is critical
    sev_count = [0] * 5
    if 'vulnerabilities' in scan_run:
        for vuln in scan_run['vulnerabilities']:
            if vuln['severity'] != None:
                sev_count[vuln['severity']] += vuln['count']

    # Count compliance checks
    # 1 is passed, 2 is warning, 3 is fail
    comp_count = [0] * 4  # Index 0 unused, 1=passed, 2=warning, 3=fail
    if compliance and 'compliance' in scan_run:
        for comp in scan_run['compliance']:
            if comp['severity'] != None:
                comp_count[comp['severity']] += comp['count']

    with connection.cursor() as cursor:
        # Insert scan run details
        sql = "INSERT INTO `scan_run` (`scan_run_id`, `scan_id`, `scan_start`,`scan_end`, `targets`, `host_count`,\
            `critical_count`, `high_count`, `medium_count`, `low_count`, `info_count`,\
            `comp_pass_count`, `comp_warning_count`, `comp_fail_count`)\
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        
        cursor.execute(sql, (
            history_id, 
            scan_id, 
            scan_run['info']['scanner_start'], 
            scan_run['info']['scanner_end'],
            scan_run['info']['targets'], 
            scan_run['info']['hostcount'],
            sev_count[4], sev_count[3], sev_count[2], sev_count[1], sev_count[0],
            comp_count[1], comp_count[2], comp_count[3]
            ))
        
        # Insert hosts in scan run
        for host in scan_run['hosts']:
            insert_host(scan_id, host['host_id'], history_id, cursor)

    connection.commit()

def update_scans():
    scans = get_scans()
    with connection.cursor() as cursor:
        # Upsert scans
        for scan in scans['scans']:
            sql = "INSERT INTO `scan` (`scan_id`, `folder_id`, `type`, `name`)\
                    VALUES (%s, %s, %s, %s)\
                    ON DUPLICATE KEY UPDATE folder_id=%s, type=%s, name=%s"
            cursor.execute(sql, (
                scan['id'], 
                scan['folder_id'], 
                scan['type'], 
                scan['name'], 
                scan['folder_id'], 
                scan['type'], 
                scan['name']
                ))
    
    connection.commit()

    for scan in scans['scans']:
        print ('Processing: ' + scan['name'])
        # Check if the scan is in a folder with type 'trash'
        folder_id = scan['folder_id']
        folder_type = next((folder['type'] for folder in scans['folders'] if folder['id'] == folder_id), None)
        
        if folder_type == 'trash' and not trash:
            if debug:
                print(f"[DEBUG] Skipping scan '{scan['name']}' in trash folder.")
            continue
        # Retreive details about the current scan
        scan_details = get_scan(scan['id'])

        if scan_details['history'] != None:
            # Check each run of each scan
            for scan_run in scan_details['history']:
                # Only import if scan finished completely
                if scan_run['status'] == 'completed':
                    
                    result = None
                    with connection.cursor() as cursor:    
                        sql = "SELECT * FROM `scan_run` WHERE `scan_run_id` = %s"
                        cursor.execute(sql, (scan_run['history_id']))
                        result = cursor.fetchone()

                    # If scan run hasn't yet been inserted
                    if result == None:
                        print ('Inserting scan run: ' + str(scan_run['history_id']))
                        insert_scan_run(scan['id'], scan_run['history_id'])
    
update_folders()
update_scans()
