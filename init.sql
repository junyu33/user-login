CREATE DATABASE IF NOT EXISTS PROJECT;
USE PROJECT;

CREATE TABLE IF NOT EXISTS user_salt (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS user_password (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    hashed_password VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS user_captcha (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    captcha VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS user_otp (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    otp VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL,
    ip VARCHAR(45) NOT NULL, -- IPv6 地址最长为 45 个字符
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_session (username, token, ip)
);

-- 假设 `user_salt` 表已经存在，并且 `username` 是唯一的，您可以设置外键约束
ALTER TABLE user_sessions ADD FOREIGN KEY (username) REFERENCES user_salt(username);
ALTER TABLE user_salt ADD UNIQUE (username);
ALTER TABLE user_otp ADD UNIQUE (username);
ALTER TABLE user_captcha ADD UNIQUE (username);
ALTER TABLE user_password ADD UNIQUE (username);
ALTER TABLE user_password ADD FOREIGN KEY (username) REFERENCES user_salt(username);

