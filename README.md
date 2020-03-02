# Nessus Professional Database Export
A script to export Nessus results regularly into a MySQL database for easy analysis/aggregation.

## Prerequisites
* Nessus Professional
* MySQL database

## Install
1. git clone https://github.com/eddiez9/nessus-database-export
2. pip3 install -r requirements.txt

## Configuration
1. Instantiate database schema (see schema.sql file for import)
2. Copy config.ini.example to config.ini and fill in all fields

## Usage
Install in crontab for scheduled exports.
```
 python3 export.py
```

### TODO
* Check if a scan run has already been imported and skip if it has
* Check existence of plugin id and insert if not exist or upsert if mod date is newer than one retrieved (currently ignores duplicate PK)
* Populate all fields for plugins (e.g. CVSS, refernces after key existence check)