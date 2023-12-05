use mysql;
CREATE USER 'kaibro'@'localhost' IDENTIFIED BY 'superbig';
GRANT SELECT ON *.* TO 'kaibro'@localhost IDENTIFIED BY 'superbig' WITH GRANT OPTION;
FLUSH PRIVILEGES;


CREATE DATABASE slot_db;
use slot_db;
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int(11) DEFAULT NULL,
  `username` text,
  `password` text
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

LOCK TABLES `users` WRITE;
INSERT INTO `users` VALUES (1, 'kaibro', '4647570f7638e378e490db41c24c800a');
UNLOCK TABLES;

CREATE DATABASE secret_db;
use secret_db;

DROP TABLE IF EXISTS `s3cret_table`;
CREATE TABLE `s3cret_table` (
  `id` int(11) DEFAULT NULL,
  `secret` text
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


LOCK TABLES `s3cret_table` WRITE;
INSERT INTO `s3cret_table` VALUES (1, 'meowmeowmeow');
UNLOCK TABLES;

