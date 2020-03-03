#!/usr/bin/env python3
import configparser
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import pymysql.cursors

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Read configuration
config = configparser.ConfigParser()
config.read('config.ini')

nessus_hostname = config.get('nessus','hostname')
nessus_port = config.get('nessus','port')
access_key = 'accessKey=' + config.get('nessus','access_key') + ';'
secret_key = 'secretKey=' + config.get('nessus','secret_key') + ';'
base = 'https://{hostname}:{port}'.format(hostname=nessus_hostname, port=nessus_port)
trash = config.getboolean('nessus','trash')

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

SCAN_RUN = SCAN_ID + '?history_id={history_id}'
HOST_VULN = HOST_ID + '?history_id={history_id}'
PLUGIN_OUTPUT = PLUGIN_ID + '?history_id={history_id}'

# Database connection
connection = pymysql.connect(host=db_hostname,
                             user=username,
                             password=password,
                             db=database,
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor,
                             autocommit=False)

# ---Functions---
# Nessus API functions
def request(url):
    url = base + url
    headers = {'X-ApiKeys': access_key + secret_key}
    response = requests.get(url=url,headers=headers,verify=False)
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

def get_plugin_output(scan_id, host_id, plugin_id, history_id):
    return request(PLUGIN_OUTPUT.format(scan_id=scan_id, host_id=host_id, plugin_id=plugin_id, history_id=history_id))

# Nessus export functions
def update_folders():
    folders = get_folders()
    with connection.cursor() as cursor:
        # Upsert folders
        for folder in folders['folders']:
            sql = "INSERT INTO `folder` (`folder_id`, `type`, `name`)\
                    VALUES (%s, %s, %s)\
                    ON DUPLICATE KEY UPDATE type=%s, name=%s"
            cursor.execute(sql, (folder['id'], folder['type'], folder['name'], folder['type'], folder['name']))
    connection.commit()

def update_plugin(plugin, cursor):
    # TODO Check existence of plugin id and insert if not exist or upsert if mod date is newer than one retrieved
    # TODO Populate all fields (e.g. CVSS, refernces after key existence check)
    sql = "INSERT IGNORE INTO `plugin` (`plugin_id`, `severity`, `name`, `family`, `synopsis`, `description`, `solution`, `pub_date`, `mod_date`)\
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
    
    cursor.execute(sql, (
        plugin['pluginid'], 
        plugin['severity'], 
        plugin['pluginname'], 
        plugin['pluginfamily'],
        plugin['pluginattributes']['synopsis'],
        plugin['pluginattributes']['description'],
        plugin['pluginattributes']['solution'],
        plugin['pluginattributes']['plugin_information'].get('plugin_publication_date', None),
        plugin['pluginattributes']['plugin_information'].get('plugin_modification_date', None)
        ))

def insert_vuln_output(scan_id, host_id, plugin_id, history_id, host_vuln_id, cursor):
    # Get vuln output
    vuln_output = get_plugin_output(scan_id, host_id, plugin_id, history_id)

    for output in vuln_output['outputs']:
        for port in output['ports'].keys():
            sql = "INSERT INTO `vuln_output` (`host_vuln_id`, `port`, `output`)\
                    VALUES (%s, %s, %s)"
            cursor.execute(sql, (host_vuln_id, port, output['plugin_output']))

    update_plugin(vuln_output['info']['plugindescription'], cursor)

def insert_host_vuln(host_id, history_id, plugin_id, cursor):
    sql = "INSERT INTO `host_vuln` (`nessus_host_id`, `scan_run_id`, `plugin_id`)\
            VALUES (%s, %s, %s)"
    cursor.execute(sql, (host_id, history_id, plugin_id))

def insert_host(scan_id, host_id, history_id, cursor):
    # Get host vulnerabilities for a scan run
    host = get_host_vuln(scan_id, host_id, history_id) 

    # Count number of vulns of each severity for this host in this scan run
    # 0 is informational, 4 is critical
    sev_count = [0] * 5
    for vuln in host['vulnerabilities']:
        sev_count[vuln['severity']] += vuln['count']
    
    # Insert host information
    sql = "INSERT INTO `host` (`nessus_host_id`, `scan_run_id`, `scan_id`, `host_ip`, `host_fqdn`, `host_start`, `host_end`, `os`,\
        `critical_count`, `high_count`, `medium_count`, `low_count`, `info_count`)\
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"

    cursor.execute(sql, (
        host_id, 
        history_id, 
        scan_id, 
        host['info']['host-ip'], 
        host['info'].get('host-fqdn', None), 
        host['info']['host_start'], 
        host['info']['host_end'], 
        host['info'].get('operating-system', None),
        sev_count[4], sev_count[3], sev_count[2], sev_count[1], sev_count[0]
        ))

    # Insert host vulnerabilities
    for vuln in host['vulnerabilities']:
        insert_host_vuln(host_id, history_id, vuln['plugin_id'], cursor)
        insert_vuln_output(scan_id, host_id, vuln['plugin_id'], history_id, cursor.lastrowid, cursor)

def insert_scan_run(scan_id, history_id):
    # Get scan runs for a scan
    scan_run = get_scan_run(scan_id, history_id)

    # Count number of vulns of each severity for this scan run
    # 0 is informational, 4 is critical
    sev_count = [0] * 5
    for vuln in scan_run['vulnerabilities']:
        sev_count[vuln['severity']] += vuln['count']

    with connection.cursor() as cursor:
        # Insert scan run details
        sql = "INSERT INTO `scan_run` (`scan_run_id`, `scan_id`, `scan_start`,`scan_end`, `targets`, `host_count`,\
            `critical_count`, `high_count`, `medium_count`, `low_count`, `info_count`)\
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        
        cursor.execute(sql, (
            history_id, 
            scan_id, 
            scan_run['info']['scanner_start'], 
            scan_run['info']['scanner_end'],
            scan_run['info']['targets'], 
            scan_run['info']['hostcount'],
            sev_count[4], sev_count[3], sev_count[2], sev_count[1], sev_count[0]
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
        
        # Retreive details about the current scan
        scan_details = get_scan(scan['id'])

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