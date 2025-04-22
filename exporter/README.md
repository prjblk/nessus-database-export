# Nessus Database Export

This tool exports Nessus scan data to a MySQL database.

## Prerequisites

- Docker installed on your system
- A valid `config.ini` file with your Nessus and MySQL credentials

## Configuration

1. Copy `config.ini.example` to `config.ini`:
   ```bash
   cp config.ini.example config.ini
   ```

2. Edit `config.ini` with your credentials:
   - Nessus hostname, port, access key, and secret key
   - MySQL hostname, username, password, and database name

## Running the Container

Build and run the container:

```bash
# Build the container
docker build -t nessus-export .

# Run the container
docker run nessus-export
```

## Configuration Options

The following options can be set in `config.ini`:

- `trash`: Set to `true` to include scans in trash folders
- `debug`: Set to `true` for debug output
- `compliance`: Set to `true` to include compliance data

## Notes

- The container will automatically run the export script when started
- Make sure your MySQL database is accessible from the container
- The Nessus server must be accessible from the container 