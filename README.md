# Nessus Professional Database Export
A script to export Nessus results regularly into a MySQL database for easy analysis/aggregation.

## Use Cases
* Find occurences of a specific vulnerability across your scans (e.g. in a folder) without having to export all of them to CSV.
* Search for text in plugin outputs across all your scans.
* Quickly see trending stats across scan runs (summary stats are calculated at export time and saved in the DB).
* Build a web app front end to present a subset of results for customers.

Some usage examples here: https://projectblack.io/blog/nessus-reporting-customisation-and-analysis/


## Prerequisites
* Nessus Professional
* MySQL database (can be run locally or in Docker)

## Installation

### Database Setup
More details can be found in `database\README.md`.
#### Option 1: Docker (Recommended)
1. Start the database container:
   ```bash
   docker compose up -d
   ```

Default passwords can be changed in the `docker-compose.yml` file.

#### Option 2: Manual Setup
1. Install MySQL on your system
2. Create a new database and user
3. Import the schema:
   ```bash
   mysql -u your_username -p your_database < database/schema.sql
   ```
4. You also have to import the stored procedures in `database/queries/*`

### Exporter Setup
More details can be found in `exporter\README.md`.
#### Configuration
1. Copy `config.ini.example` to `config.ini`:
   ```bash
   cp config.ini.example config.ini
   ```

2. Configure the following in `config.ini`:
   - Nessus hostname, port, access key, and secret key
   - MySQL hostname, username, password, and database name
   - Additional options:
     - `trash`: Set to `true` to include scans in trash folders
     - `debug`: Set to `true` for debug output
     - `compliance`: Set to `true` to include compliance data

#### Option 1: Docker
1. Build the exporter container:
   ```bash
   cd exporter
   docker build -t nessus-export .
   ```

2. Run the exporter:
   ```bash
   docker run nessus-export
   ```

#### Option 2: Manual Setup
1. Install Python dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

## Usage
The exporter can be run in two ways:

### Docker
```bash
docker run nessus-export
```

### Manual
```bash
python3 export.py
```

Example output:
```
Processing: REDACTED
Inserting scan run: 69
Inserting scan run: 81
Processing: REDACTED
Processing: REDACTED
Inserting scan run: 87
```

Once the export is completed you can run whatever queries you want. e.g.:

<img src="https://i.imgur.com/fehc7j3.png">

## TODO and NOTES
* TODO: Add flag to only retrieve latest scan
* TODO: Possibly build more samples if there's interest?
* NOTE: Compliance scans are experimental, try it and let me know if it works?
