#!/usr/bin/env python3
import configparser
import requests
import pymysql.cursors

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
SCAN_RUN_ID = SCAN_ID + '?history_id={history_id}'
HOST_VULN = SCAN_ID + '/hosts/{host_id}'
PLUGINS = HOST_VULN + '/plugins/{plugin_id}'

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

def get_scan_id(id):
    return request(SCAN_ID.format(scan_id=id))

def get_scan_run_id(scan_id, history_id):
    return request(SCAN_RUN_ID.format(scan_id=scan_id, history_id=history_id))

# Nessus export functions
def update_folders():
    folders = get_folders()
    with connection.cursor() as cursor:
        for folder in folders['folders']:
            sql = "INSERT INTO `folder` (`folder_id`, `type`, `name`)\
                    VALUES (%s, %s, %s)\
                    ON DUPLICATE KEY UPDATE type=%s, name=%s"
            cursor.execute(sql, (folder['id'], folder['type'], folder['name'], folder['type'], folder['name']))
    connection.commit()

def insert_scan_run(scan_id, history_id):
    scan_run = get_scan_run_id(scan_id, history_id)

    with connection.cursor() as cursor:

    
    connection.commit()

def update_scans():
    scans = get_scans()
    with connection.cursor() as cursor:
        for scan in scans['scans']:
            sql = "INSERT INTO `scan` (`scan_id`, `folder_id`, `type`, `name`)\
                    VALUES (%s, %s, %s, %s)\
                    ON DUPLICATE KEY UPDATE folder_id=%s, type=%s, name=%s"
            cursor.execute(sql, (scan['id'], scan['folder_id'], scan['type'], scan['name'], scan['folder_id'], scan['type'], scan['name']))
    connection.commit()

    for scan in scans['scans']:
        # Retreive details about the current scan
        scan_details = get_scan_id(scan['id'])

        # Check each run of each scan
        for scan_run in scan_details['history']:
            # If the scan has finished
            if (scan_run['status'] != 'running') OR (scan_run['status'] != 'paused'):
                # TODO If we haven't already saved this scan run
                insert_scan_run(scan['id'], scan_run['history_id'])

        


update_folders()
update_scans()