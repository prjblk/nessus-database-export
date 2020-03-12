-- Run SQL to install stored procedure
-- Get scan results for scans in a folder given a folder_id
-- Get all scan results for most recent scans in folder_id 100 by running CALL get_folder_results(100, 0)

DROP PROCEDURE IF EXISTS get_folder_results;

DELIMITER //
CREATE PROCEDURE get_folder_results
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
        host_vuln_id INT(11),
        plugin_id INT(11), 
        nessus_host_id INT(11), 
        scan_run_id INT(11), 
        host_id INT(11), 
        scan_id INT(11), 
        host_ip VARCHAR(45), 
        host_fqdn VARCHAR(255), 
        host_start VARCHAR(255), 
        host_end VARCHAR(255), 
        os LONGTEXT, 
        critical_count INT(11), 
        high_count INT(11), 
        medium_count INT(11), 
        low_count INT(11), 
        info_count INT(11), 
        severity INT(11), 
        name LONGTEXT, 
        family LONGTEXT, 
        synopsis LONGTEXT, 
        description LONGTEXT, 
        solution LONGTEXT, 
        cvss_base_score DOUBLE, 
        cvss3_base_score DOUBLE, 
        cvss_vector VARCHAR(45), 
        cvss3_vector VARCHAR(45), 
        ref LONGTEXT, 
        pub_date VARCHAR(45), 
        mod_date VARCHAR(45), 
        vuln_output_id INT(11), 
        port VARCHAR(45), 
        output LONGTEXT
    );

   OPEN cur_list;

   loop_list: LOOP
        FETCH cur_list INTO cur_scan_id;
        IF cur_done THEN
            LEAVE loop_list;
        END IF;
		
        INSERT INTO temp_table (host_vuln_id, plugin_id, nessus_host_id, scan_run_id, host_id, scan_id, host_ip, host_fqdn, host_start, host_end, os, critical_count, high_count, medium_count, low_count, info_count, severity, name, family, synopsis, description, solution, cvss_base_score, cvss3_base_score, cvss_vector, cvss3_vector, ref, pub_date, mod_date, vuln_output_id, port, output)
        SELECT * FROM host 
        NATURAL JOIN host_vuln 
        NATURAL JOIN plugin 
        NATURAL JOIN vuln_output 
        WHERE scan_run_id = 
        (SELECT scan_run_id FROM nessusdb.scan_run 
        NATURAL JOIN nessusdb.scan 
        WHERE nessusdb.scan_run.scan_id = cur_scan_id 
        ORDER BY scan_start DESC
        LIMIT 1
        OFFSET offset);

		END LOOP loop_list;
   CLOSE cur_list;

   SELECT * FROM temp_table;

END //
DELIMITER ;
