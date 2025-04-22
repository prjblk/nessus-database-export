-- Grant all privileges on nessusdb to nessususer
GRANT ALL PRIVILEGES ON nessusdb.* TO 'nessususer'@'%';
FLUSH PRIVILEGES; 