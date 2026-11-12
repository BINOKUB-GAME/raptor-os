# RAPTOR-OS & RAPTOR DEFENSE v2.0 (Baseline)
Système souverain sous OpenBSD 8.0 intégrant :
- `raptor-core/` : Sentinelle noyau `kqueue` (`EVFILT_VNODE`), riposte réflexe (`SIGSTOP`/`SIGKILL`), boîte noire RAM (`/raptor_blackbox`) et console réseau `netop`.
- `system/` : Service `rc.d`, politique pare-feu `pf.conf` (`<badhosts>`), routage `syslog.conf`, rotation `newsyslog.conf` et manuel `rap(8)`.
