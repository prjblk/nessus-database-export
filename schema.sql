CREATE DATABASE  IF NOT EXISTS `nessusdb` /*!40100 DEFAULT CHARACTER SET utf8mb4 */;
USE `nessusdb`;
-- MySQL dump 10.13  Distrib 8.0.19, for Win64 (x86_64)
--
-- Host: 192.168.1.169    Database: nessusdb
-- ------------------------------------------------------
-- Server version	5.7.29-0ubuntu0.16.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `folder`
--

DROP TABLE IF EXISTS `folder`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `folder` (
  `folder_id` int(11) NOT NULL,
  `type` varchar(45) DEFAULT NULL,
  `name` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`folder_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `host`
--

DROP TABLE IF EXISTS `host`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `host` (
  `host_id` int(11) NOT NULL AUTO_INCREMENT,
  `nessus_host_id` int(11) DEFAULT NULL,
  `scan_run_id` int(11) DEFAULT NULL,
  `scan_id` int(11) DEFAULT NULL,
  `host_ip` varchar(45) DEFAULT NULL,
  `host_fqdn` varchar(255) DEFAULT NULL,
  `host_start` varchar(255) DEFAULT NULL,
  `host_end` varchar(255) DEFAULT NULL,
  `os` longtext,
  `critical_count` int(11) DEFAULT NULL,
  `high_count` int(11) DEFAULT NULL,
  `medium_count` int(11) DEFAULT NULL,
  `low_count` int(11) DEFAULT NULL,
  `info_count` int(11) DEFAULT NULL,
  PRIMARY KEY (`host_id`),
  KEY `fk_host_scan_id_idx` (`scan_id`),
  KEY `fk_host_scan_run_id_idx` (`scan_run_id`),
  KEY `host_nessus_host_id_idx` (`nessus_host_id`),
  CONSTRAINT `fk_host-scan` FOREIGN KEY (`scan_id`) REFERENCES `scan` (`scan_id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `fk_host-scan_run` FOREIGN KEY (`scan_run_id`) REFERENCES `scan_run` (`scan_run_id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `host_vuln`
--

DROP TABLE IF EXISTS `host_vuln`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `host_vuln` (
  `host_vuln_id` int(11) NOT NULL AUTO_INCREMENT,
  `nessus_host_id` int(11) DEFAULT NULL,
  `scan_run_id` int(11) DEFAULT NULL,
  `plugin_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`host_vuln_id`),
  KEY `fk_host_scan_run_id_idx` (`scan_run_id`),
  KEY `fk_host_vuln-host_idx` (`nessus_host_id`),
  KEY `fk_host_vuln-plugin_idx` (`plugin_id`),
  -- CONSTRAINT `fk_host_vuln-host` FOREIGN KEY (`nessus_host_id`) REFERENCES `host` (`nessus_host_id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `fk_host_vuln-plugin` FOREIGN KEY (`plugin_id`) REFERENCES `plugin` (`plugin_id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `fk_host_vuln-scan_run` FOREIGN KEY (`scan_run_id`) REFERENCES `scan_run` (`scan_run_id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `plugin`
--

DROP TABLE IF EXISTS `plugin`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `plugin` (
  `plugin_id` int(11) NOT NULL,
  `severity` int(11) DEFAULT NULL,
  `name` longtext,
  `family` longtext,
  `synopsis` longtext,
  `description` longtext,
  `solution` longtext,
  `cvss_base_score` double DEFAULT NULL,
  `cvss3_base_score` double DEFAULT NULL,
  `cvss_vector` varchar(45) DEFAULT NULL,
  `cvss3_vector` varchar(45) DEFAULT NULL,
  `ref` longtext,
  `pub_date` varchar(45) DEFAULT NULL,
  `mod_date` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`plugin_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scan`
--

DROP TABLE IF EXISTS `scan`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scan` (
  `scan_id` int(11) NOT NULL,
  `folder_id` int(11) DEFAULT NULL,
  `type` varchar(45) DEFAULT NULL,
  `name` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`scan_id`),
  KEY `fk_folder_id_idx` (`folder_id`),
  CONSTRAINT `fk_scan-folder` FOREIGN KEY (`folder_id`) REFERENCES `folder` (`folder_id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scan_run`
--

DROP TABLE IF EXISTS `scan_run`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scan_run` (
  `scan_run_id` int(11) NOT NULL,
  `scan_id` int(11) DEFAULT NULL,
  `scan_start` int(11) DEFAULT NULL,
  `scan_end` int(11) DEFAULT NULL,
  `targets` longtext,
  `host_count` int(11) DEFAULT NULL,
  `critical_count` int(11) DEFAULT NULL,
  `high_count` int(11) DEFAULT NULL,
  `medium_count` int(11) DEFAULT NULL,
  `low_count` int(11) DEFAULT NULL,
  `info_count` int(11) DEFAULT NULL,
  PRIMARY KEY (`scan_run_id`),
  KEY `fk_scan_id_idx` (`scan_id`),
  CONSTRAINT `fk_scan_run-scan` FOREIGN KEY (`scan_id`) REFERENCES `scan` (`scan_id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vuln_output`
--

DROP TABLE IF EXISTS `vuln_output`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vuln_output` (
  `vuln_output_id` int(11) NOT NULL AUTO_INCREMENT,
  `host_vuln_id` int(11) DEFAULT NULL,
  `port` varchar(45) DEFAULT NULL,
  `output` longtext,
  PRIMARY KEY (`vuln_output_id`),
  KEY `fk_vuln_output-host_vuln_id_idx` (`host_vuln_id`),
  CONSTRAINT `fk_vuln_output-host_vuln` FOREIGN KEY (`host_vuln_id`) REFERENCES `host_vuln` (`host_vuln_id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-03-05 21:35:27
