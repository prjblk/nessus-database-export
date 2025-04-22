FROM mysql:8.0

# Copy initialization scripts
COPY schema.sql /docker-entrypoint-initdb.d/01-schema.sql
COPY queries/*.sql /docker-entrypoint-initdb.d/02-procedures.sql
COPY init-permissions.sql /docker-entrypoint-initdb.d/03-permissions.sql

# Set permissions
RUN chown -R mysql:mysql /docker-entrypoint-initdb.d/ 