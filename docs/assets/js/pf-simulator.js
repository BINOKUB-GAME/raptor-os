/**
 * ============================================================================
 * NOM DU SCRIPT : assets/js/pf-simulator.js
 * NUMÉRO DE RÉVISION : Révision 1.0
 * ----------------------------------------------------------------------------
 * BLOC DESCRIPTIF DES INTÉGRATIONS :
 * Moteur de simulation pédagogique interactif pour CENTURION / RAPTOR-OS 2.0
 * (OpenBSD/amd64).
 * - Simule le traitement des paquets réseau entrants sur l'interface Intel em0.
 * - Illustre en temps réel l'action du pare-feu noyau Packet Filter (pf), des
 *   tables dynamiques (<partenaires_paiement> et <bruteforce>), du confinement
 *   applicatif C (pledge / unveil) et du verrouillage noyau kern.securelevel=1.
 * - Alimente un terminal simulé du journal immuable '/raptor_blackbox' et
 *   propose un mode Stress Test automatisé.
 * ----------------------------------------------------------------------------
 * INDEX NUMÉROTÉ DES FONCTIONS :
 * 1. initialiserSimulateur()        : Point d'entrée principal au chargement du DOM.
 * 2. attacherEvenementsCommandes()  : Relie les boutons de scénarios et d'outils.
 * 3. executerSimulation()           : Orchestre le cycle complet d'un flux réseau.
 * 4. animerPipelineEtapes()         : Anime séquentiellement les 4 étages du bastion.
 * 5. mettreAJourReglePfActive()     : Surligne la directive /etc/pf.conf déclenchée.
 * 6. ajouterIpBruteforce()          : Ajoute une IP hostile dans la table <bruteforce>.
 * 7. actualiserTablesEtCompteurs()  : Met à jour les compteurs et listes d'IP.
 * 8. ajouterEntreeBlackbox()        : Inscrit une ligne horodatée dans /raptor_blackbox.
 * 9. basculerModeStressTest()       : Active ou coupe l'injection automatique mixte.
 * 10. reinitialiserSimulateur()     : Remet à zéro compteurs, bannissements et journal.
 * 11. attacherCopieTerminal()       : Permet la copie presse-papiers du journal simulé.
 * 12. echapperHtml()                : Assainit les chaînes affichées dans le DOM.
 * ============================================================================
 */

(function () {
    "use strict";

    /** État interne isolé du simulateur */
    const etatSim = {
        paquetsEm0: 0,
        transactionsValidees: 0,
        attaquesBloquees: 0,
        latenceCouranteMs: 1.2,
        partenairesWhitelist: [
            { ip: "192.0.2.15", label: "Terminal-POS-01" },
            { ip: "192.0.2.28", label: "Passerelle-Banque-A" },
            { ip: "198.51.100.10", label: "Noeud-Compensation" }
        ],
        bruteforceBlacklist: [],
        timersAnimation: [],
        intervalleStress: null
    };

    /** Catalogue des scénarios simulables */
    const SCENARIOS_FLUX = {
        "tx-legitime": {
            idRegle: "rule-pass-partner",
            statutFlux: "pass",
            latenceMs: 1.2,
            etapes: [
                { nodeId: "node-em0", etat: "state-pass", texte: "TRAME REÇUE (1 Gbit/s)" },
                { nodeId: "node-pf", etat: "state-pass", texte: "PASS (<partenaires_paiement>)" },
                { nodeId: "node-c", etat: "state-pass", texte: "ISO-8583 VALIDÉ (pledge OK)" },
                { nodeId: "node-bb", etat: "state-pass", texte: "COMMIT SQL + LOG APPEND" }
            ],
            logNiveau: "log-pass",
            logMessage: "[INTERFACE:em0] [SRC:192.0.2.15] [DST:TCP/443] Paquet authentifié (<partenaires_paiement>) -> Parseur C statique OK -> Transaction enregistrée (1.2 ms)."
        },
        "scan-port": {
            idRegle: "rule-block-default",
            statutFlux: "drop",
            latenceMs: 1.1,
            ipHostile: "203.0.113.77",
            motifBan: "Sonde SSH/22",
            etapes: [
                { nodeId: "node-em0", etat: "state-drop", texte: "SONDE TCP SYN :22" },
                { nodeId: "node-pf", etat: "state-drop", texte: "BLOCK DROP QUICK (FURTIF)" },
                { nodeId: "node-c", etat: "state-bypassed", texte: "NON SOLLICITÉ" },
                { nodeId: "node-bb", etat: "state-drop", texte: "TRACE REJET ENREGISTRÉE" }
            ],
            logNiveau: "log-drop",
            logMessage: "[PF:DROP_SILENT] [INTERFACE:em0] [SRC:203.0.113.77] [DST:TCP/22] Port fermé -> Aucun paquet RST émis | IP ajoutée à <bruteforce>."
        },
        "sqli-payload": {
            idRegle: "rule-block-bruteforce",
            statutFlux: "drop",
            latenceMs: 1.3,
            ipHostile: "198.51.100.91",
            motifBan: "Payload SQLi",
            etapes: [
                { nodeId: "node-em0", etat: "state-drop", texte: "REQUÊTE HTTPS MALFORMÉE" },
                { nodeId: "node-pf", etat: "state-drop", texte: "REJET / BASCULE <bruteforce>" },
                { nodeId: "node-c", etat: "state-drop", texte: "PARSEUR STRICT (UNVEIL OK)" },
                { nodeId: "node-bb", etat: "state-drop", texte: "ALERTE INTÉGRITÉ LOGUÉE" }
            ],
            logNiveau: "log-drop",
            logMessage: "[UNVEIL/PF:BLOCK] [INTERFACE:em0] [SRC:198.51.100.91] Charge non conforme (' OR 1=1) -> Rejet immédiat sans accès disque | IP bannie dans <bruteforce>."
        },
        "syn-flood": {
            idRegle: "rule-synproxy",
            statutFlux: "drop",
            latenceMs: 1.4,
            ipHostile: "203.0.113.144",
            motifBan: "SYN Flood 45k/s",
            etapes: [
                { nodeId: "node-em0", etat: "state-drop", texte: "RAFALE 45 000 SYN/S" },
                { nodeId: "node-pf", etat: "state-drop", texte: "SYNPROXY + RATE-LIMIT" },
                { nodeId: "node-c", etat: "state-bypassed", texte: "PROTÉGÉ (0% SATURATION)" },
                { nodeId: "node-bb", etat: "state-drop", texte: "312 IP -> <bruteforce>" }
            ],
            logNiveau: "log-drop",
            logMessage: "[PF:SYNPROXY] [INTERFACE:em0] Rafale TCP SYN absorbée par le noyau OpenBSD -> Table <bruteforce> mise à jour | Voie <partenaires_paiement> stable à 1.4 ms."
        },
        "tamper-kernel": {
            idRegle: "rule-securelevel",
            statutFlux: "lock",
            latenceMs: 1.2,
            etapes: [
                { nodeId: "node-em0", etat: "state-bypassed", texte: "INTERNE (LOCALHOST)" },
                { nodeId: "node-pf", etat: "state-lock", texte: "RÈGLES VERROUILLÉES (schg)" },
                { nodeId: "node-c", etat: "state-lock", texte: "PLEDGE : EPERM INTERDIT" },
                { nodeId: "node-bb", etat: "state-lock", texte: "SECURELEVEL=1 : IMMUABLE" }
            ],
            logNiveau: "log-lock",
            logMessage: "[KERNEL:SECURELEVEL=1] Tentative d'écriture sur /etc/pf.conf et /raptor_blackbox refusée (Operation not permitted — drapeaux schg/sappnd actifs)."
        }
    };

    /**
     * 1. Point d'entrée principal au chargement du DOM.
     */
    function initialiserSimulateur() {
        const panneauControles = document.getElementById("sim-controls");
        if (!panneauControles) {
            return;
        }
        attacherEvenementsCommandes();
        attacherCopieTerminal();
        actualiserTablesEtCompteurs();
    }

    /**
     * 2. Relie les boutons de scénarios, le mode Stress Test et la réinitialisation.
     */
    function attacherEvenementsCommandes() {
        document.querySelectorAll("[data-sim-scenario]").forEach(function (bouton) {
            bouton.addEventListener("click", function () {
                const cle = this.getAttribute("data-sim-scenario");
                executerSimulation(cle);
            });
        });

        const btnStress = document.getElementById("sim-btn-stress");
        if (btnStress) {
            btnStress.addEventListener("click", basculerModeStressTest);
        }

        const btnReset = document.getElementById("sim-btn-reset");
        if (btnReset) {
            btnReset.addEventListener("click", reinitialiserSimulateur);
        }
    }

    /**
     * 3. Orchestre le cycle complet d'un flux réseau à travers RAPTOR-OS 2.0.
     */
    function executerSimulation(typeScenario) {
        const config = SCENARIOS_FLUX[typeScenario];
        if (!config) {
            return;
        }

        etatSim.paquetsEm0 += (typeScenario === "syn-flood" ? 450 : 1);
        etatSim.latenceCouranteMs = config.latenceMs;

        if (config.statutFlux === "pass") {
            etatSim.transactionsValidees += 1;
        } else {
            etatSim.attaquesBloquees += 1;
        }

        if (config.ipHostile) {
            ajouterIpBruteforce(config.ipHostile, config.motifBan);
        }

        animerPipelineEtapes(config.etapes);
        mettreAJourReglePfActive(config.idRegle, config.statutFlux);
        actualiserTablesEtCompteurs();
        ajouterEntreeBlackbox(config.logNiveau, config.logMessage);
    }

    /**
     * 4. Anime séquentiellement les 4 étages du bastion (em0 -> pf -> C -> Blackbox).
     */
    function animerPipelineEtapes(etapes) {
        etatSim.timersAnimation.forEach(function (timerId) {
            clearTimeout(timerId);
        });
        etatSim.timersAnimation = [];

        document.querySelectorAll(".sim-node").forEach(function (noeud) {
            noeud.classList.remove("state-pass", "state-drop", "state-lock", "state-bypassed");
        });

        etapes.forEach(function (etape, index) {
            const timer = setTimeout(function () {
                const noeudDom = document.getElementById(etape.nodeId);
                if (!noeudDom) {
                    return;
                }
                noeudDom.classList.add(etape.etat);
                const badgeStatut = noeudDom.querySelector(".sim-node-status");
                if (badgeStatut) {
                    badgeStatut.textContent = etape.texte;
                }
            }, index * 110);

            etatSim.timersAnimation.push(timer);
        });
    }

    /**
     * 5. Met en évidence la directive exacte de /etc/pf.conf déclenchée.
     */
    function mettreAJourReglePfActive(idRegle, statutFlux) {
        document.querySelectorAll(".pf-rule-line").forEach(function (ligne) {
            ligne.classList.remove("rule-hit-pass", "rule-hit-drop", "rule-hit-lock");
        });

        const ligneCible = document.getElementById(idRegle);
        if (!ligneCible) {
            return;
        }

        if (statutFlux === "pass") {
            ligneCible.classList.add("rule-hit-pass");
        } else if (statutFlux === "lock") {
            ligneCible.classList.add("rule-hit-lock");
        } else {
            ligneCible.classList.add("rule-hit-drop");
        }
    }

    /**
     * 6. Insère dynamiquement une IP hostile dans la table mémoire <bruteforce>.
     */
    function ajouterIpBruteforce(ipSource, motif) {
        const existeDeja = etatSim.bruteforceBlacklist.some(function (item) {
            return item.ip === ipSource;
        });

        if (!existeDeja) {
            etatSim.bruteforceBlacklist.unshift({
                ip: ipSource,
                motif: motif
            });
        }
    }

    /**
     * 7. Met à jour les compteurs télémétriques et les tables mémoire pf.
     */
    function actualiserTablesEtCompteurs() {
        const elEm0 = document.getElementById("metric-em0");
        const elPass = document.getElementById("metric-pass");
        const elDrop = document.getElementById("metric-drop");
        const elBan = document.getElementById("metric-ban");
        const elLat = document.getElementById("metric-latency");

        if (elEm0) {
            elEm0.textContent = etatSim.paquetsEm0.toLocaleString("fr-CA");
        }
        if (elPass) {
            elPass.textContent = etatSim.transactionsValidees.toLocaleString("fr-CA");
        }
        if (elDrop) {
            elDrop.textContent = etatSim.attaquesBloquees.toLocaleString("fr-CA");
        }
        if (elBan) {
            elBan.textContent = etatSim.bruteforceBlacklist.length.toString();
        }
        if (elLat) {
            elLat.textContent = etatSim.latenceCouranteMs.toFixed(1) + " ms";
        }

        const listeWhite = document.getElementById("table-whitelist");
        if (listeWhite) {
            listeWhite.innerHTML = etatSim.partenairesWhitelist.map(function (item) {
                return "<li><span>" + echapperHtml(item.ip) + '</span><span class="ip-tag-muted">' + echapperHtml(item.label) + "</span></li>";
            }).join("");
        }

        const listeBlack = document.getElementById("table-blacklist");
        if (listeBlack) {
            if (etatSim.bruteforceBlacklist.length === 0) {
                listeBlack.innerHTML = '<li><span class="ip-tag-muted">Aucune IP bannie actuellement</span></li>';
            } else {
                listeBlack.innerHTML = etatSim.bruteforceBlacklist.map(function (item) {
                    return "<li><span>" + echapperHtml(item.ip) + '</span><span class="ip-tag-muted">' + echapperHtml(item.motif) + "</span></li>";
                }).join("");
            }
        }
    }

    /**
     * 8. Inscrit une ligne horodatée dans le terminal immuable /raptor_blackbox.
     */
    function ajouterEntreeBlackbox(classeNiveau, message) {
        const terminal = document.getElementById("sim-terminal-body");
        if (!terminal) {
            return;
        }

        const horodatage = new Date().toISOString().replace("T", " ").substring(0, 19) + "Z";
        const ligne = document.createElement("div");
        ligne.className = "log-entry " + classeNiveau;
        ligne.textContent = "[" + horodatage + "] [BLACKBOX] " + message;

        terminal.insertBefore(ligne, terminal.firstChild);

        while (terminal.children.length > 35) {
            terminal.removeChild(terminal.lastChild);
        }
    }

    /**
     * 9. Démarre ou arrête l'injection automatique de trafic mixte (Stress Test).
     */
    function basculerModeStressTest() {
        const btnStress = document.getElementById("sim-btn-stress");
        if (!btnStress) {
            return;
        }

        if (etatSim.intervalleStress !== null) {
            clearInterval(etatSim.intervalleStress);
            etatSim.intervalleStress = null;
            btnStress.classList.remove("stress-active");
            btnStress.textContent = "Activer Stress Test continu";
            ajouterEntreeBlackbox("log-info", "[SIMULATEUR] Arrêt du générateur de charge mixte.");
            return;
        }

        const sequenceMixte = ["tx-legitime", "scan-port", "tx-legitime", "syn-flood", "sqli-payload", "tx-legitime"];
        let indexSequence = 0;

        btnStress.classList.add("stress-active");
        btnStress.textContent = "Arrêter Stress Test (En cours...)";
        ajouterEntreeBlackbox("log-info", "[SIMULATEUR] Démarrage du banc de charge mixte sur em0...");

        executerSimulation(sequenceMixte[0]);
        etatSim.intervalleStress = setInterval(function () {
            indexSequence = (indexSequence + 1) % sequenceMixte.length;
            executerSimulation(sequenceMixte[indexSequence]);
        }, 1400);
    }

    /**
     * 10. Remet à zéro les compteurs, la table <bruteforce> et le journal simulé.
     */
    function reinitialiserSimulateur() {
        if (etatSim.intervalleStress !== null) {
            basculerModeStressTest();
        }

        etatSim.paquetsEm0 = 0;
        etatSim.transactionsValidees = 0;
        etatSim.attaquesBloquees = 0;
        etatSim.latenceCouranteMs = 1.2;
        etatSim.bruteforceBlacklist = [];

        document.querySelectorAll(".sim-node").forEach(function (noeud) {
            noeud.classList.remove("state-pass", "state-drop", "state-lock", "state-bypassed");
            const badge = noeud.querySelector(".sim-node-status");
            if (badge) {
                badge.textContent = "EN ATTENTE";
            }
        });

        document.querySelectorAll(".pf-rule-line").forEach(function (ligne) {
            ligne.classList.remove("rule-hit-pass", "rule-hit-drop", "rule-hit-lock");
        });

        const terminal = document.getElementById("sim-terminal-body");
        if (terminal) {
            terminal.innerHTML = '<div class="log-entry log-info">[INIT] Interface Intel em0 prête — Packet Filter (pf) actif — kern.securelevel=1 verrouillé.</div>';
        }

        actualiserTablesEtCompteurs();
    }

    /**
     * 11. Active la copie rapide du contenu du terminal /raptor_blackbox.
     */
    function attacherCopieTerminal() {
        const boutonCopie = document.getElementById("sim-copy-logs");
        const terminal = document.getElementById("sim-terminal-body");
        if (!boutonCopie || !terminal) {
            return;
        }

        boutonCopie.addEventListener("click", function () {
            const lignes = Array.from(terminal.querySelectorAll(".log-entry")).map(function (el) {
                return el.textContent;
            }).join("\n");

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(lignes).then(function () {
                    boutonCopie.textContent = "Journal copié ✓";
                    setTimeout(function () {
                        boutonCopie.textContent = "Copier le journal";
                    }, 2000);
                });
            }
        });
    }

    /**
     * 12. Assainit les chaînes de caractères contre toute injection XSS.
     */
    function echapperHtml(chaine) {
        return String(chaine)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    document.addEventListener("DOMContentLoaded", initialiserSimulateur);
})();
