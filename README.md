# RAPTOR-OS — Distribution Durcie & Appliance Web-to-DB (amd64)

**RAPTOR-OS** est un système d'exploitation autonome construit sur un socle **OpenBSD/amd64** (`kern.securelevel=1`), intégrant un pare-feu applicatif temps réel (`RAPTOR-HTTPD/2.0`), une boîte noire forensique en mémoire partagée (`/raptor_blackbox`), une sonde d'audit SQL (`raptor-sql-sentry`) et des passerelles C-CGI confinées par `chroot` et `pledge(2)`.

---

## 1. Installation complète sur machine physique dédiée (Recommandé)

Cette méthode installe simultanément le système d'exploitation et l'ensemble des composants **RAPTOR-OS** précompilés (`site80.tgz`) sur un serveur ou PC dédié :

1. Téléchargez **`raptor-os-2.0-amd64.iso`** (845 Mo) et **`raptor-os-2.0-amd64.iso.sha256`** depuis l'onglet **[Releases](../../releases/latest)** de ce dépôt.
2. Vérifiez l'empreinte d'intégrité (`SHA256`) avant écriture :

       05ef0bea698e1e29b28323e06a58744a2e370b738220f8ce23d92f51140aef0e  raptor-os-2.0-amd64.iso

3. Copiez l'image ISO hybride (BIOS + UEFI) sur une clé USB vierge (`sdX` = périphérique USB) :

       sudo dd if=raptor-os-2.0-amd64.iso of=/dev/sdX bs=4M status=progress conv=fsync

4. Démarrez la machine dédiée sur la clé USB et suivez l'installeur en conservant l'ensemble **`site80.tgz`** sélectionné (`[X] site80.tgz`).
5. Au premier démarrage, les mots de passe MariaDB uniques générés automatiquement pour cette machine se trouvent dans `/root/RAPTOR_CREDENTIALS.txt`.

---

## 2. Arborescence du dépôt

* **`raptor-core/` :** Sources C natives (`raptor-httpd`, `rap`, `raptor-db-cgi`, `raptor-sql-sentry`) et passerelle `www/db_test.php`.
* **`system/` :** Configurations système (`etc/httpd.conf`, `etc/pf.conf`, `etc/motd`, `etc/issue.net`, `etc/rc.d/`).
* **`install.sh` :** Script de déploiement depuis les sources sur un socle OpenBSD/amd64 existant.
* **`LICENSE` :** Licence ISC et attribution amont à The OpenBSD Project.

---

## 3. Déploiement depuis les sources (Développeurs / Système existant)

Sur une installation OpenBSD/amd64 déjà en place (en tant que `root`) :

    pkg_add git
    git clone https://github.com/BINOKUB-GAME/raptor-os.git
    cd raptor-os
    RAPTOR_APP_PASS="VotreMotDePasseApp!" RAPTOR_ROOT_PASS="VotreMotDePasseRoot!" ksh install.sh

---

## Licence

Distribué sous **licence ISC** avec attribution amont à **The OpenBSD Project**. Consultez le fichier [`LICENSE`](LICENSE) pour les détails complets.
