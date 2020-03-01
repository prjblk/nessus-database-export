# nessus-database-export
A script to export Nessus results regularly into a MySQL database for easy analysis/aggregation.

## Prerequisites
* Nessus Professional
* MySQL database

## Install
1. git clone https://github.com/eddiez9/nessus-database-export
2. pip3 install -r requirements.txt

## Configuration
1. Instantiate database schema
2. Copy config.ini.example to config.ini and fill in all fields

## Usage
Install in crontab for scheduled exports.
```
 python3 export.py
```