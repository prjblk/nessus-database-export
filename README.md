# Nessus Professional Database Export
A script to export Nessus results regularly into a MySQL database for easy analysis/aggregation.

## Use Cases
* Find occurences of a specific vulnerability across your scans (e.g. in a folder) without having to export all of them to CSV.
* Search for text in plugin outputs across all your scans.
* Quickly see trending stats across scan runs (summary stats are calculated at export time and saved in the DB).
* Build a web app front end to present a subset of results for customers.

## Prerequisites
* Nessus Professional
* MySQL database

## Install
1. git clone https://github.com/eddiez9/nessus-database-export
2. pip3 install -r requirements.txt

## Configuration
1. Instantiate database schema (see schema.sql file for import)

    e.g. at the mysql command line
    mysql> source \home\user\Desktop\schema.sql;
2. Copy config.ini.example to config.ini and fill in all fields

## Usage
Install in crontab for scheduled exports or run manually by just calling the script with no arguments:
```
$ python3 export.py
Processing: REDACTED
Inserting scan run: 69
Inserting scan run: 81
Processing: REDACTED
Processing: REDACTED
Inserting scan run: 87
```
Once the export is completed you can run whatever queries you want. e.g.:

<img src="https://i.imgur.com/fehc7j3.png">

### TODO
* Check API output for compliance scans and add code to pull in compliance scans
* Use trash flag to not pull in scans in the trash