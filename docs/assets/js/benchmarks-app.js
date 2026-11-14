/**
 * ============================================================================
 * NOM DU SCRIPT : assets/js/benchmarks-app.js
 * NUMÉRO DE RÉVISION : Révision 1.0
 * ----------------------------------------------------------------------------
 * BLOC DESCRIPTIF DES INTÉGRATIONS :
 * Module autonome de rendu des bancs d'essai matériels Bare-Metal pour
 * CENTURION / RAPTOR-OS 2.0 (docs/benchmarks.html).
 * - Charge dynamiquement les spécifications matérielles et les campagnes de
 *   mesures depuis 'assets/data/benchmarks.json'.
 * - Intègre un jeu de données de secours embarqué pour le test local hors-ligne
 *   (protocole file:// sous Debian 13) sans blocage CORS.
 * - Gère la copie rapide des commandes d'audit reproductibles OpenBSD.
 * ----------------------------------------------------------------------------
 * INDEX NUMÉROTÉ DES FONCTIONS :
 * 1. initialiserBenchmarks()      : Point d'entrée principal au chargement du DOM.
 * 2. chargerDonneesBenchmarks()   : Récupère benchmarks.json ou active le repli local.
 * 3. obtenirDonneesSecours()      : Retourne les données embarquées pour test file://.
 * 4. afficherFicheMaterielle()    : Rend la carte de configuration du ThinkPad T490.
 * 5. afficherCampagnesTest()      : Génère les cartes de tests et mesures SLA.
 * 6. attacherBoutonsCopie()       : Active la copie presse-papiers des commandes d'audit.
 * 7. echapperHtml()               : Assainit les chaînes contre toute injection XSS.
 * ============================================================================
 */

(function () {
    "use strict";

    /**
     * 1. Point d'entrée principal au chargement du DOM.
     */
    function initialiserBenchmarks() {
        const conteneur = document.getElementById("bm-campaigns");
        if (!conteneur) {
            return;
        }
        chargerDonneesBenchmarks();
    }

    /**
     * 2. Récupère assets/data/benchmarks.json ou bascule sur le repli local.
     */
    async function chargerDonneesBenchmarks() {
        let donnees = null;

        try {
            if (window.location.protocol === "file:") {
                donnees = obtenirDonneesSecours();
            } else {
                const reponse = await fetch("assets/data/benchmarks.json", { cache: "no-store" });
                if (!reponse.ok) {
                    throw new Error("Erreur HTTP " + reponse.status);
                }
                donnees = await reponse.json();
            }
        } catch (erreur) {
            console.warn("[RAPTOR-OS Benchmarks] Mode repli local activé :", erreur.message);
            donnees = obtenirDonneesSecours();
        }

        if (donnees) {
            afficherFicheMaterielle(donnees.plateforme_materielle);
            afficherCampagnesTest(donnees.campagnes || []);
        }
    }

    /**
     * 3. Retourne les données embarquées pour prévisualisation locale (file://).
     */
    function obtenirDonneesSecours() {
        return {
            plateforme_materielle: {
                modele: "Lenovo ThinkPad T490 (Bare-Metal Dédié)",
                processeur: "Intel Core i5-8265U (4 cœurs / 8 threads, 1.60 GHz – Turbo 3.90 GHz)",
                memoire: "16 Go DDR4",
                stockage: "256 Go SSD NVMe (nvme0 / sd0)",
                interface_reseau: "Intel Ethernet Connection I219-LM (em0 — 1000baseT full-duplex)",
                systeme: "CENTURION / RAPTOR-OS 2.0 (OpenBSD 8.0 / amd64, kern.securelevel=1)",
                banc_client: "Poste Debian 13 (dan-dev) relié par câble Ethernet RJ-45 isolé"
            },
            campagnes: [
                {
                    id: "bench-01-transactions-c",
                    code: "TEST 01 · DÉBIT & LATENCE",
                    titre: "Passerelle transactionnelle C natif (raptor_db_post + MariaDB 127.0.0.1)",
                    objectif_sla: "Latence moyenne < 2,0 ms | 0 erreur SQL sous rafale légitime",
                    valeur_mesuree: "En attente de livraison T490",
                    statut: "PRÊT POUR MESURE",
                    protocole: "Envoi de 10 000 requêtes POST transactionnelles paramétrées depuis dan-dev sur le port 443 de l'interface em0, avec validation double pledge(2) et écriture MariaDB locale.",
                    commande_audit: "wrk -t4 -c64 -d30s --latency https://192.168.1.50/cgi-bin/raptor_db_post"
                },
                {
                    id: "bench-02-pf-synproxy",
                    code: "TEST 02 · PARE-FEU NOYAU PF",
                    titre: "Absorption SYN Flood & priorisation <partenaires_paiement> sur em0",
                    objectif_sla: "100 % des IP hostiles bannies dans <bruteforce> | Latence partenaire < 2,5 ms",
                    valeur_mesuree: "En attente de livraison T490",
                    statut: "PRÊT POUR MESURE",
                    protocole: "Saturation TCP SYN haute cadence simulée depuis dan-dev pendant l'exécution simultanée de transactions autorisées afin de mesurer l'isolation matérielle du contrôleur Intel em0.",
                    commande_audit: "pfctl -t bruteforce -T show && pfctl -si"
                },
                {
                    id: "bench-03-waf-canary",
                    code: "TEST 03 · CONFINEMENT & CANARY",
                    titre: "Rejet WAF pré-exécution, chroot / pledge(2) et sonde raptor_vault_canary",
                    objectif_sla: "Blocage 100 % des charges SQLi/XSS | Alerte < 10 ms dans /raptor_blackbox",
                    valeur_mesuree: "En attente de livraison T490",
                    statut: "PRÊT POUR MESURE",
                    protocole: "Injection automatisée de traversées de répertoires, caractères de contrôle et sondes sur la table piège raptor_vault_canary pour vérifier la réaction immédiate de raptor_sql_sentry.",
                    commande_audit: "rap status && tail -n 20 /raptor_blackbox/audit.log"
                },
                {
                    id: "bench-04-empreinte-securelevel",
                    code: "TEST 04 · EMPREINTE & IMMUABILITÉ",
                    titre: "Consommation RAM réelle et verrouillage noyau kern.securelevel=1",
                    objectif_sla: "Empreinte RAM totale < 220 Mo | Refus EPERM sur modification /etc/pf.conf",
                    valeur_mesuree: "En attente de livraison T490",
                    statut: "PRÊT POUR MESURE",
                    protocole: "Relevé de la mémoire vive occupée par les 6 démons actifs et test d'écriture forcée sous privilèges root sur les règles pf et les binaires marqués schg/sappnd.",
                    commande_audit: "top -b -n 1 | head -n 12 && sysctl kern.securelevel"
                }
            ]
        };
    }

    /**
     * 4. Affiche la fiche de configuration matérielle du ThinkPad T490.
     */
    function afficherFicheMaterielle(hw) {
        const panneau = document.getElementById("bm-hardware");
        if (!panneau || !hw) {
            return;
        }

        const specs = [
            { label: "Châssis & Architecture", val: hw.modele },
            { label: "Processeur", val: hw.processeur },
            { label: "Mémoire & Stockage", val: hw.memoire + " · " + hw.stockage },
            { label: "Contrôleur Ethernet", val: hw.interface_reseau },
            { label: "Système & Durcissement", val: hw.systeme },
            { label: "Banc d'injection client", val: hw.banc_client }
        ];

        const itemsHtml = specs.map(function (sp) {
            return (
                '<div class="bm-hw-item">' +
                    '<div class="bm-hw-label">' + echapperHtml(sp.label) + '</div>' +
                    '<div class="bm-hw-val">' + echapperHtml(sp.val) + '</div>' +
                '</div>'
            );
        }).join("");

        panneau.innerHTML =
            '<div class="bm-hw-header">' +
                '<h2>Plateforme Matérielle de Référence</h2>' +
                '<span class="bm-hw-badge">BARE-METAL · INTERFACE EM0</span>' +
            '</div>' +
            '<div class="bm-hw-grid">' + itemsHtml + '</div>';
    }

    /**
     * 5. Affiche l'ensemble des campagnes de tests et leurs relevés SLA.
     */
    function afficherCampagnesTest(campagnes) {
        const grille = document.getElementById("bm-campaigns");
        if (!grille) {
            return;
        }

        grille.innerHTML = campagnes.map(function (camp, idx) {
            const estValide = camp.statut && camp.statut.toUpperCase().indexOf("VALID") !== -1;
            const classeStatut = estValide ? "status-validated" : "status-pending";
            const idCode = "bm-cmd-" + idx;

            return (
                '<article class="bm-card">' +
                    '<div>' +
                        '<div class="bm-card-top">' +
                            '<span class="bm-code">' + echapperHtml(camp.code) + '</span>' +
                            '<span class="bm-status ' + classeStatut + '">' + echapperHtml(camp.statut) + '</span>' +
                        '</div>' +
                        '<h3>' + echapperHtml(camp.titre) + '</h3>' +
                        '<div class="bm-metrics-box">' +
                            '<div class="bm-metric-row"><strong>Objectif SLA :</strong> ' + echapperHtml(camp.objectif_sla) + '</div>' +
                            '<div class="bm-metric-row"><strong>Mesure relevée :</strong> ' + echapperHtml(camp.valeur_mesuree) + '</div>' +
                        '</div>' +
                        '<p class="bm-proto">' + echapperHtml(camp.protocole) + '</p>' +
                    '</div>' +
                    '<div class="bm-cmd-box">' +
                        '<code id="' + idCode + '">' + echapperHtml(camp.commande_audit) + '</code>' +
                        '<button type="button" class="bm-copy-btn" data-copy-target="' + idCode + '">Copier</button>' +
                    '</div>' +
                '</article>'
            );
        }).join("");

        attacherBoutonsCopie();
    }

    /**
     * 6. Active les boutons de copie rapide des commandes d'audit OpenBSD.
     */
    function attacherBoutonsCopie() {
        document.querySelectorAll(".bm-copy-btn").forEach(function (btn) {
            btn.addEventListener("click", function () {
                const cibleId = this.getAttribute("data-copy-target");
                const elCode = document.getElementById(cibleId);
                if (!elCode || !navigator.clipboard) {
                    return;
                }
                const boutonCourant = this;
                navigator.clipboard.writeText(elCode.textContent || "").then(function () {
                    boutonCourant.textContent = "Copié ✓";
                    setTimeout(function () {
                        boutonCourant.textContent = "Copier";
                    }, 1800);
                });
            });
        });
    }

    /**
     * 7. Assainit les chaînes contre toute injection XSS.
     */
    function echapperHtml(chaine) {
        return String(chaine)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    document.addEventListener("DOMContentLoaded", initialiserBenchmarks);
})();
