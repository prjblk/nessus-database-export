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
update_all = config.getboolean('nessus','update_all')

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
                             cursorclass=pymysql.cursors.DictCursor)

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



# def insert_host_vuln(host_id, scan_run_id, plugin_id, cursor):

def insert_host(scan_id, host_id, history_id, cursor):
    host = get_host_vuln(scan_id, host_id, history_id)

    # Count number of vulns of each severity for this host in this scan run
    # 0 is informational, 4 is critical
    sev_count = [0] * 5
    for vuln in host['vulnerabilities']:
        sev_count[vuln['severity']] += vuln['count']
        
    if (host_id == 5):
        print(sev_count)


def insert_scan_run(scan_id, history_id):
    scan_run = get_scan_run(scan_id, history_id)

    # Count number of vulns of each severity for this scan run
    # 0 is informational, 4 is critical
    sev_count = [0] * 5
    for vuln in scan_run['vulnerabilities']:
        sev_count[vuln['severity']] += vuln['count']

    with connection.cursor() as cursor:
        # Insert scan run details
        sql = "INSERT INTO `scan_run` (`scan_run_id`, `scan_id`, `scan_start`, `scan_end`, `targets`, `host_count`, `critical_count`, `high_count`, `medium_count`, `low_count`, `info_count`)\
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        # cursor.execute(sql, (history_id, scan_id, scan_run['info']['scanner_start'], scan_run['info']['scanner_end'], scan_run['info']['targets'], scan_run['info']['hostcount'], sev_count[4], sev_count[3], sev_count[2], sev_count[1], sev_count[0]))
        
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
            cursor.execute(sql, (scan['id'], scan['folder_id'], scan['type'], scan['name'], scan['folder_id'], scan['type'], scan['name']))
    connection.commit()

    for scan in scans['scans']:
        print ('Processing:' + scan['name'])
        
        # Retreive details about the current scan
        scan_details = get_scan(scan['id'])

        # Check each run of each scan
        for scan_run in scan_details['history']:
            # If the scan has finished
            if ((scan_run['status'] != 'running') or (scan_run['status'] != 'paused')):
                # TODO If we haven't already saved this scan run
                insert_scan_run(scan['id'], scan_run['history_id'])

        


update_folders()
update_scans()