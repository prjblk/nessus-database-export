-- Run SQL to install stored procedure
-- Stored procedure to grab the scan stats for the most recent run given a scan_id
-- e.g. To get the most recent scan stats for scan_id 100 CALL get_scan_stats(100, 0)

DROP PROCEDURE IF EXISTS get_scan_stats;

DELIMITER //
CREATE PROCEDURE get_scan_stats
(IN sid INT, IN offset INT)
BEGIN
	SELECT * FROM nessusdb.scan_run 
    NATURAL JOIN nessusdb.scan 
    WHERE nessusdb.scan_run.scan_id = sid 
    ORDER BY scan_start DESC
    LIMIT 1
    OFFSET offset;
END //
DELIMITER ;
