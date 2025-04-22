# Nessus Database Docker Setup

This directory contains the Docker configuration for the Nessus database, which stores scan results and vulnerability data.

## Structure

- `Dockerfile` - MySQL database configuration
- `schema.sql` - Database schema definition
- `queries/` - Directory containing stored procedures
- `init-permissions.sql` - SQL script to set up user permissions

## Quick Start

1. Make sure you have Docker and Docker Compose installed
2. From the root directory, run:
   ```bash
   docker-compose up -d
   ```

## Database Access

The database will by default be accessible with these credentials, change the docker-compose file to change this:
- Database: nessusdb
- Username: nessususer
- Password: nessuspassword

## Data Persistence

Data is stored in a Docker volume named `mysql_data`. This ensures that your data persists even if the container is stopped or removed.

## Stopping the Database

To stop the database:
```bash
docker-compose down
```

To stop and remove all data (including the volume):
```bash
docker-compose down -v
```

## Notes

- The database is configured to automatically restart unless explicitly stopped
- The schema and stored procedures are automatically loaded on first run
- The nessususer has full privileges on the nessusdb database 