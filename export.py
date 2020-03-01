import configparser
import requests

# Read configuration
config = configparser.ConfigParser()
config.read('config.ini')

# Nessus endpoints
FOLDERS = '/folders'
SCANS = '/scans'
SCAN_ID = SCANS + '/{scan_id}'
HOST_VULN = SCAN_ID + '/hosts/{host_id}'
PLUGINS = HOST_VULN + '/plugins/{plugin_id}'

port = config.get('nessus','port')
hostname = config.get('nessus','hostname')
access_key = 'accessKey=' + config.get('nessus','access_key') + ';'
secret_key = 'secretKey=' + config.get('nessus','secret_key') + ';'
base = 'https://{hostname}:{port}'.format(hostname=hostname, port=port)

# Functions
def request(url, json_output=False):
    url = base + url
    headers = {'X-ApiKeys': access_key + secret_key}
    response = requests.get(url=url,headers=headers,verify=False)
    return response.json()

def get_scans():
    return request(SCANS)

def get_folders():
    return request(FOLDERS)

def get_scan_id(id):
    return request(SCAN_ID.format(scan_id=id))



