-- Run SQL to install stored procedure
-- Stored procedure to grab the results for the most recent run given a scan_id
-- e.g. To get the most recent scan for scan_id 100 CALL get_scan_results(100, 0)

DROP PROCEDURE IF EXISTS get_scan_results;

DELIMITER //
CREATE PROCEDURE get_scan_results
(IN sid INT, IN offset INT)
BEGIN
	SELECT * FROM nessusdb.host 
	NATURAL JOIN nessusdb.host_vuln 
	NATURAL JOIN nessusdb.plugin 
	NATURAL JOIN nessusdb.vuln_output 
	WHERE scan_run_id = 
		(SELECT scan_run_id FROM nessusdb.scan_run 
		NATURAL JOIN nessusdb.scan 
		WHERE nessusdb.scan_run.scan_id = sid 
		ORDER BY scan_start DESC
		LIMIT 1
        OFFSET offset);
END //
DELIMITER ;
