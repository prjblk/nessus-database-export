-- Run SQL to install stored
-- Get summary stats for scans in a folder given a folder_id
-- Get most recent scan stats for folder_id 100 by running CALL get_folder_stats(100, 0)

DROP PROCEDURE IF EXISTS get_folder_stats;

DELIMITER //
CREATE PROCEDURE get_folder_stats
(IN fid INT, IN offset INT)

BEGIN
    DECLARE cur_done BOOLEAN DEFAULT FALSE;
    DECLARE cur_scan_id INT;
    
    DECLARE cur_list CURSOR FOR 
        SELECT scan_id FROM nessusdb.scan 
		WHERE folder_id = fid;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET cur_done = TRUE;
    DROP TEMPORARY TABLE IF EXISTS temp_table;
    CREATE TEMPORARY TABLE temp_table
    (
        scan_id INT(11),
        scan_run_id INT(11),        
        scan_start INT(11),
        scan_end INT(11),
        targets LONGTEXT,
        host_count INT(11),
        critical_count INT(11),
        high_count INT(11),
        medium_count INT(11),
        low_count INT(11),
        info_count INT(11),
        folder_id INT(11),
        type VARCHAR(45),
        name VARCHAR(45)
    );

   OPEN cur_list;

   loop_list: LOOP
        FETCH cur_list INTO cur_scan_id;
        IF cur_done THEN
            LEAVE loop_list;
        END IF;
		
        INSERT INTO temp_table (scan_id, scan_run_id, scan_start, scan_end, targets, host_count, critical_count, high_count, medium_count, low_count, info_count, folder_id, type, name)
        SELECT * FROM nessusdb.scan_run 
		NATURAL JOIN nessusdb.scan 
		WHERE nessusdb.scan_run.scan_id = cur_scan_id 
		ORDER BY scan_start DESC
		LIMIT 1
		OFFSET offset;

		END LOOP loop_list;
   CLOSE cur_list;

   SELECT * FROM temp_table;

END //
DELIMITER ;
