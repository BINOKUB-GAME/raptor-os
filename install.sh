#!/bin/ksh
# ==============================================================================
# SCRIPT      : install.sh
# REVISION    : 1.0
# DESCRIPTION : Installeur modulaire et automatise de RAPTOR-OS sur socle
#               OpenBSD/amd64. Deploie l'arborescence du depot (raptor-core/
#               et system/), installe MariaDB 12.3 et PHP 8.5 FPM, compile les
#               passerelles C-CGI confinees par pledge(2) et raptor-sql-sentry,
#               initialise la base raptor_db avec table piege canary, applique
#               le rebranding visible RAPTOR-OS et active les 6 services rcctl.
#
# FONCTIONS NUMEROTEES :
#   01. check_environment       - Verification des droits root et du socle OS
#   02. install_dependencies    - Installation des paquets MariaDB et PHP-FPM
#   03. build_raptor_core       - Compilation et installation de raptor-core/
#   04. deploy_system_configs   - Deploiement de system/etc/ et passerelle PHP
#   05. harden_mariadb          - Creation base raptor_db, comptes et canary
#   06. apply_rebranding_start  - Identite RAPTOR-OS et demarrage des 6 demons
# ==============================================================================

set -e

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
APP_PASS="${RAPTOR_APP_PASS:-RaptorApp_ChangeMe_2026!}"
ROOT_PASS="${RAPTOR_ROOT_PASS:-RaptorRoot_ChangeMe_2026!}"

# 01. Verification des droits root et du socle OS
check_environment() {
    echo "[01/06] Verification de l'environnement systeme..."
    if [ "$(id -u)" -ne 0 ]; then
        echo "ERREUR : Ce script doit etre execute en tant que root."
        exit 1
    fi
    if [ "$(uname -s)" != "OpenBSD" ]; then
        echo "ERREUR : Socle OpenBSD/amd64 requis."
        exit 1
    fi
}

# 02. Installation des paquets MariaDB et PHP-FPM
install_dependencies() {
    echo "[02/06] Installation des paquets MariaDB et PHP 8.5..."
    pkg_add -I mariadb-server php%8.5 php-pdo_mysql%8.5
    ln -sf /etc/php-8.5.sample/pdo_mysql.ini /etc/php-8.5/pdo_mysql.ini 2>/dev/null || true
}

# 03. Compilation et installation de raptor-core/
build_raptor_core() {
    echo "[03/06] Compilation des modules C dans raptor-core/..."
    mkdir -p /usr/local/src /var/www/cgi-bin /var/www/run /var/www/htdocs
    cp -R "$REPO_ROOT/raptor-core/"* /usr/local/src/
    rm -rf /usr/local/src/www

    for dir in /usr/local/src/*; do
        if [ -f "$dir/Makefile" ]; then
            echo "  -> Compilation de $(basename "$dir")"
            (cd "$dir" && make clean && make && make install)
        fi
    done
}

# 04. Deploiement de system/etc/ et passerelle PHP
deploy_system_configs() {
    echo "[04/06] Deploiement des configurations system/ et de la passerelle PHP..."
    if [ -f "$REPO_ROOT/raptor-core/www/db_test.php" ]; then
        sed "s/CHANGE_ME_RAPTOR_APP_PASS/$APP_PASS/g" "$REPO_ROOT/raptor-core/www/db_test.php" > /var/www/htdocs/db_test.php
        chmod 0644 /var/www/htdocs/db_test.php
    fi

    cp "$REPO_ROOT/system/etc/httpd.conf" /etc/httpd.conf
    [ -f "$REPO_ROOT/system/etc/pf.conf" ] && cp "$REPO_ROOT/system/etc/pf.conf" /etc/pf.conf
    cp "$REPO_ROOT/system/etc/rc.d/raptor"* /etc/rc.d/ 2>/dev/null || true
    chmod 0555 /etc/rc.d/raptor* 2>/dev/null || true

    chown -R www:www /var/www/run
    chmod 0755 /var/www/run
}

# 05. Creation base raptor_db, comptes et canary
harden_mariadb() {
    echo "[05/06] Initialisation et durcissement de MariaDB..."
    if [ ! -d /var/mysql/mysql ]; then
        mariadb-install-db --user=_mysql --basedir=/usr/local --datadir=/var/mysql
    fi
    rcctl enable mysqld
    rcctl start mysqld

    cat << SQL | mariadb --no-defaults -u root
CREATE DATABASE IF NOT EXISTS raptor_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE raptor_db;

CREATE TABLE IF NOT EXISTS raptor_status (
    id INT AUTO_INCREMENT PRIMARY KEY,
    component VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS raptor_vault_canary (
    id INT PRIMARY KEY,
    secret_token VARCHAR(128) NOT NULL
);

INSERT IGNORE INTO raptor_vault_canary (id, secret_token) VALUES (1, 'CANARY_TRAP_DO_NOT_TOUCH');

DELIMITER //
DROP TRIGGER IF EXISTS trg_raptor_canary_guard//
CREATE TRIGGER trg_raptor_canary_guard BEFORE UPDATE ON raptor_vault_canary
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'RAPTOR_SQL_CANARY_BREACH';
END//
DELIMITER ;

CREATE USER IF NOT EXISTS 'raptor_app'@'127.0.0.1' IDENTIFIED BY '$APP_PASS';
GRANT SELECT, INSERT ON raptor_db.* TO 'raptor_app'@'127.0.0.1';

ALTER USER 'root'@'localhost' IDENTIFIED BY '$ROOT_PASS';
DROP USER IF EXISTS ''@'localhost';
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
SQL

    printf '[client]\nuser=root\npassword="%s"\n' "$ROOT_PASS" > /root/.my.cnf
    chmod 0600 /root/.my.cnf
}

# 06. Identite RAPTOR-OS et demarrage des 6 demons
apply_rebranding_start() {
    echo "[06/06] Application de l'identite RAPTOR-OS et demarrage des services..."
    cp "$REPO_ROOT/system/etc/issue.net" /etc/issue.net
    cp "$REPO_ROOT/system/etc/motd" /etc/motd

    if ! grep -q "RAPTOR-OS/%m" /etc/gettytab; then
        cp /etc/gettytab /etc/gettytab.bak
        sed 's|%s/%m|RAPTOR-OS/%m|g' /etc/gettytab.bak > /etc/gettytab
    fi

    if ! grep -q 'sed "s/OpenBSD/RAPTOR-OS/g' /etc/rc; then
        cp /etc/rc /etc/rc.bak
        sed 's#sysctl -n kern.version | sed 1q >$T#sysctl -n kern.version | sed "s/OpenBSD/RAPTOR-OS/g;1q" >$T#' /etc/rc.bak > /etc/rc.new
        [ -s /etc/rc.new ] && mv /etc/rc.new /etc/rc && chmod 0644 /etc/rc
    fi

    [ -f /etc/pf.conf ] && pfctl -f /etc/pf.conf
    rcctl enable raptor mysqld raptor_sql_sentry slowcgi php85_fpm httpd
    rcctl restart raptor mysqld raptor_sql_sentry slowcgi php85_fpm httpd
    echo "Deploiement RAPTOR-OS termine avec succes."
}

check_environment
install_dependencies
build_raptor_core
deploy_system_configs
harden_mariadb
apply_rebranding_start
