CREATE DATABASE IF NOT EXISTS unistrategist;
USE unistrategist;

CREATE TABLE IF NOT EXISTS users (
  id INT NOT NULL AUTO_INCREMENT,
  name VARCHAR(50) COLLATE utf8mb4_general_ci NOT NULL,
  birthdate DATE NOT NULL,
  grade INT NOT NULL,
  username VARCHAR(50) COLLATE utf8mb4_general_ci NOT NULL,
  password VARCHAR(255) COLLATE utf8mb4_general_ci NOT NULL,
  school_name VARCHAR(100) COLLATE utf8mb4_general_ci DEFAULT NULL,
  consent TINYINT(1) NOT NULL,
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


CREATE TABLE IF NOT EXISTS analysis_history (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,             
  target_univ VARCHAR(100),                 
  target_major VARCHAR(100),                
  analysis_type VARCHAR(20),                
  extracted_text TEXT,                      
  analysis_result TEXT,                     
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user_id (user_id)
);

CREATE TABLE `essay_history` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `user_id` INT NOT NULL,
    `target_univ` VARCHAR(50) COLLATE utf8mb4_general_ci DEFAULT NULL,
    `file_name` VARCHAR(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
    `title` VARCHAR(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
    `questions_json` LONGTEXT COLLATE utf8mb4_general_ci,
    `student_answers_json` LONGTEXT COLLATE utf8mb4_general_ci,
    `grading_result` LONGTEXT COLLATE utf8mb4_general_ci,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (`id`),
    KEY `user_id` (`user_id`),
    
    CONSTRAINT `essay_history_ibfk_1`
        FOREIGN KEY (`user_id`)
        REFERENCES `users` (`id`)
        ON DELETE CASCADE
) ENGINE=InnoDB 
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_general_ci
  AUTO_INCREMENT=5;
