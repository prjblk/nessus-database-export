-- Run SQL to install stored procedure
-- Get scan results for scans in a folder given a folder_id
-- Get all scan results for most recent scans in folder_id 100 by running CALL get_folder_results(100, NULL, 0)
-- If you want to filter out a specific existences of a specific vulnerability you can use the second parameter to specify a plugin_id CALL get_folder_results(100, 10287, 0)

DROP PROCEDURE IF EXISTS get_folder_results;

DELIMITER //
CREATE PROCEDURE get_folder_results
(IN fid INT, IN pid INT, IN offset INT)

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
        host_ip VARCHAR(255), 
        host_fqdn VARCHAR(255), 
        host_start VARCHAR(255), 
        host_end VARCHAR(255), 
        os LONGTEXT, 
        critical_count INT(11), 
        high_count INT(11), 
        medium_count INT(11), 
        low_count INT(11), 
        info_count INT(11),
        comp_warning_count INT(11),
        comp_pass_count INT(11),
        comp_fail_count INT(11),
        severity INT(11), 
        name LONGTEXT, 
        family LONGTEXT, 
        synopsis LONGTEXT, 
        description LONGTEXT, 
        solution LONGTEXT, 
        cvss_base_score DOUBLE, 
        cvss3_base_score DOUBLE, 
        cvss_vector VARCHAR(255), 
        cvss3_vector VARCHAR(255), 
        ref LONGTEXT, 
        pub_date VARCHAR(255), 
        mod_date VARCHAR(255),
        policy_value LONGTEXT,
        vuln_output_id INT(11), 
        port VARCHAR(255), 
        output LONGTEXT
    );

    OPEN cur_list;

    loop_list: LOOP
            FETCH cur_list INTO cur_scan_id;
            IF cur_done THEN
                LEAVE loop_list;
            END IF;
            
            INSERT INTO temp_table (host_vuln_id, plugin_id, nessus_host_id, scan_run_id, host_id, scan_id, host_ip, host_fqdn, host_start, host_end, os, critical_count, high_count, medium_count, low_count, info_count, comp_warning_count, comp_pass_count, comp_fail_count, severity, name, family, synopsis, description, solution, cvss_base_score, cvss3_base_score, cvss_vector, cvss3_vector, ref, pub_date, mod_date, policy_value, vuln_output_id, port, output)
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

    IF pid IS NULL THEN
        SELECT * FROM temp_table;
    ELSE 
        SELECT * FROM temp_table WHERE plugin_id = pid;
    END IF;

END //
DELIMITER ;
