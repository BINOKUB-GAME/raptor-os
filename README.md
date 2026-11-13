# RAPTOR-OS — Appliance de Défense Active & Passerelles Web-to-DB

**RAPTOR-OS** est une architecture système et défensive durcie construite sur un socle **OpenBSD/amd64** (`kern.securelevel=1`), intégrant un pare-feu applicatif temps réel (`RAPTOR-HTTPD/2.0`), une boîte noire forensique en mémoire partagée (`/raptor_blackbox`), une sonde d'audit SQL (`raptor-sql-sentry`) et des passerelles C-CGI confinées par `chroot` et `pledge(2)`.

---

## Arborescence du dépôt

* **`raptor-core/` :** Sources C natives (`raptor-httpd`, `rap`, `raptor-db-cgi`, `raptor-sql-sentry`) et passerelle `www/db_test.php`.
* **`system/` :** Configurations système (`etc/httpd.conf`, `etc/pf.conf`, `etc/motd`, `etc/issue.net`, `etc/rc.d/`).
* **`install.sh` :** Script d'installation et de durcissement automatisé.
* **`LICENSE` :** Licence ISC et attribution amont à The OpenBSD Project.

---

## Installation rapide sur OpenBSD/amd64

Sur une machine OpenBSD fraîchement installée (en tant que `root`) :

    pkg_add git
    git clone https://github.com/VOTRE_COMPTE/raptor-os.git
    cd raptor-os
    RAPTOR_APP_PASS="VotreMotDePasseApp!" RAPTOR_ROOT_PASS="VotreMotDePasseRoot!" ksh install.sh

---

## Licence

Distribué sous **licence ISC** avec attribution amont à **The OpenBSD Project**. Consultez le fichier [`LICENSE`](LICENSE) pour les détails complets.
