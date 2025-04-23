FROM mysql:8.0

# Copy initialization scripts
COPY schema.sql /docker-entrypoint-initdb.d/01-schema.sql
COPY queries/get-scan-stats.sql /docker-entrypoint-initdb.d/02-scan-stats.sql
COPY queries/get-scan-results.sql /docker-entrypoint-initdb.d/03-scan-results.sql
COPY queries/get-compliance-results.sql /docker-entrypoint-initdb.d/04-compliance-results.sql
COPY queries/get-folder-stats.sql /docker-entrypoint-initdb.d/05-folder-stats.sql
COPY queries/get-folder-results.sql /docker-entrypoint-initdb.d/06-folder-results.sql
COPY init-permissions.sql /docker-entrypoint-initdb.d/07-permissions.sql

# Set permissions
RUN chown -R mysql:mysql /docker-entrypoint-initdb.d/ 