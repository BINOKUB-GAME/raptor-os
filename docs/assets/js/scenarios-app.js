/**
 * ============================================================================
 * NOM DU SCRIPT : js/scenarios-app.js
 * NUMÉRO DE RÉVISION : Révision 1.0
 * ----------------------------------------------------------------------------
 * BLOC DESCRIPTIF DES INTÉGRATIONS :
 * Module autonome de gestion et d'affichage interactif du Laboratoire Post-Mortem
 * pour CENTURION / RAPTOR-OS 2.0.
 * - Charge dynamiquement les scénarios d'attaques depuis 'data/scenarios.json'.
 * - Intègre un jeu de données de secours embarqué pour le test local hors-ligne
 *   (protocole file:// sous Debian 13) sans blocage CORS.
 * - Permet le filtrage par catégorie de menace et la comparaison visuelle entre
 *   un serveur classique et le bouclier OpenBSD (pf, pledge, unveil, securelevel).
 * - Gère la copie rapide des journaux simulés de '/raptor_blackbox'.
 * ----------------------------------------------------------------------------
 * INDEX NUMÉROTÉ DES FONCTIONS :
 * 1. initialiserLaboratoire()      : Point d'entrée principal au chargement du DOM.
 * 2. chargerScenarios()            : Récupère data/scenarios.json ou active le repli local.
 * 3. obtenirDonneesSecours()       : Retourne les scénarios embarqués pour prévisualisation file://.
 * 4. construireFiltresCategories() : Génère dynamiquement les boutons de filtre par catégorie.
 * 5. filtrerEtAfficher()           : Filtre la liste selon la catégorie active et met à jour la vue.
 * 6. afficherSelecteurScenarios()  : Affiche les cartes de sélection des attaques filtrées.
 * 7. afficherDiagnosticScenario()  : Rend le comparatif complet (Classique vs RAPTOR-OS + Blackbox).
 * 8. attacherCopieJournal()        : Active le bouton de copie du journal /raptor_blackbox.
 * 9. echapperHtml()                : Assainit les chaînes de caractères contre toute injection XSS.
 * ============================================================================
 */

(function () {
    "use strict";

    /** État interne isolé du module */
    const etatModule = {
        tousLesScenarios: [],
        categorieActive: "Toutes",
        scenarioActifId: null
    };

    /**
     * 1. Point d'entrée principal au chargement du DOM.
     */
    function initialiserLaboratoire() {
        const conteneurPrincipal = document.getElementById("pm-viewer");
        if (!conteneurPrincipal) {
            return;
        }
        chargerScenarios();
    }

    /**
     * 2. Récupère data/scenarios.json via fetch() ou bascule sur le repli local.
     */
    async function chargerScenarios() {
        try {
            if (window.location.protocol === "file:") {
                etatModule.tousLesScenarios = obtenirDonneesSecours();
            } else {
                const reponse = await fetch("assets/data/scenarios.json", { cache: "no-store" });
                if (!reponse.ok) {
                    throw new Error("Erreur HTTP " + reponse.status);
                }
                const donnees = await reponse.json();
                etatModule.tousLesScenarios = Array.isArray(donnees.scenarios) ? donnees.scenarios : [];
            }
        } catch (erreur) {
            console.warn("[RAPTOR-OS Post-Mortem] Chargement repli local activé :", erreur.message);
            etatModule.tousLesScenarios = obtenirDonneesSecours();
        }

        if (etatModule.tousLesScenarios.length > 0) {
            etatModule.scenarioActifId = etatModule.tousLesScenarios[0].id;
            construireFiltresCategories();
            filtrerEtAfficher();
        }
    }

    /**
     * 3. Retourne les scénarios embarqués pour test local direct (file://).
     */
    function obtenirDonneesSecours() {
        return [
            {
                id: "log4shell-rce",
                annee: "2021",
                cve: "CVE-2021-44228",
                categorie: "Injection & RCE",
                titre: "Log4Shell — Exécution de code à distance via JNDI",
                gravite: "Critique (CVSS 10.0)",
                resume: "Un attaquant injecte une chaîne JNDI piégée dans un simple en-tête HTTP (User-Agent). Le serveur interprète la chaîne, contacte un serveur LDAP malveillant et exécute du code arbitraire à distance.",
                serveur_classique: {
                    titre: "Serveur Applicatif Classique (Linux / Java / Stack lourde)",
                    etapes: [
                        "Le serveur web transmet l'en-tête HTTP non filtré au moteur de journalisation applicatif.",
                        "La bibliothèque dynamique résout la requête JNDI et initie une connexion sortante vers l'IP de l'attaquant.",
                        "Une classe malveillante est chargée en mémoire : prise de contrôle totale du serveur et pivot vers la base de données."
                    ]
                },
                bouclier_raptor: {
                    titre: "Architecture CENTURION / RAPTOR-OS 2.0",
                    mecanismes: [
                        "Zéro JVM et zéro interpréteur dynamique : les passerelles transactionnelles sont compilées en C pur statique.",
                        "Filtrage sortant strict Packet Filter (pf) : toute connexion TCP/UDP initiée depuis le bastion vers l'extérieur est bloquée par défaut (block out all).",
                        "Confinement noyau pledge(2) et unveil(2) : le processus réseau n'a aucun droit d'exécution de sous-processus (execve interdit)."
                    ]
                },
                blackbox_log: "[2026-11-14T09:12:04Z] [BLACKBOX][IMMUTABLE] [INTERFACE:em0] [SRC:198.51.100.42] [PROTO:TCP/443] Rejet syntaxique parseur C (caractères de contrôle non conformes ISO-8583/JSON) -> Paquet détruit (DROP) | Sortie sortante : BLOQUÉE par pf."
            },
            {
                id: "webshell-ransomware",
                annee: "2023",
                cve: "CVE-2023-34362",
                categorie: "Injection & RCE",
                titre: "Type MOVEit — Injection SQL, dépôt de Webshell et Rançongiciel",
                gravite: "Critique (CVSS 9.8)",
                resume: "Exploitation d'une faille d'injection SQL sur un portail exposé permettant de déposer un script exécutable dans le répertoire web, puis de chiffrer les données de l'entreprise.",
                serveur_classique: {
                    titre: "Serveur Web Exposé Classique (IIS / PHP / Node.js)",
                    etapes: [
                        "L'injection SQL contourne l'authentification et écrit un fichier exécutable dans le dossier public du serveur.",
                        "Le moteur web interprète le script déposé avec les droits du service applicatif.",
                        "L'intrus extrait les clés de base de données, chiffre les volumes et efface les journaux locaux."
                    ]
                },
                bouclier_raptor: {
                    titre: "Architecture CENTURION / RAPTOR-OS 2.0",
                    mecanismes: [
                        "Système de fichiers cloisonné : la racine web (httpd chrooté) est montée sans permission d'exécution et sans interpréteur.",
                        "Verrouillage noyau kern.securelevel=1 : les binaires critiques, les règles pf et les journaux sont protégés par le drapeau immuable (schg).",
                        "Requêtes SQL exclusivement préparées (Prepared Statements) dans la passerelle C avec validation stricte des types."
                    ]
                },
                blackbox_log: "[2026-11-14T10:04:19Z] [BLACKBOX][IMMUTABLE] [UNVEIL:VIOLATION] Tentative d'accès écriture hors périmètre chroot par worker PID 4812 -> Signal SIGKILL immédiat du noyau OpenBSD | Intégrité disque : 100% intacte."
            },
            {
                id: "syn-flood-gateway",
                annee: "2024",
                cve: "DDoS L4",
                categorie: "Réseau & DDoS",
                titre: "Saturation SYN Flood & Scan furtif sur passerelle de paiement",
                gravite: "Élevée (Disponibilité)",
                resume: "Un botnet envoie des dizaines de milliers de requêtes TCP SYN semi-ouvertes par seconde pour saturer la file d'attente réseau et bloquer les terminaux de paiement légitimes.",
                serveur_classique: {
                    titre: "Serveur Standard sans filtrage matériel/noyau",
                    etapes: [
                        "La pile TCP alloue une structure mémoire pour chaque paquet SYN usurpé reçu.",
                        "En moins de 15 secondes, la table des connexions atteint sa limite maximale.",
                        "Les terminaux de paiement légitimes reçoivent des erreurs Timeout et les transactions échouent."
                    ]
                },
                bouclier_raptor: {
                    titre: "Architecture CENTURION / RAPTOR-OS 2.0",
                    mecanismes: [
                        "Interface Ethernet Intel dédiée (em0) optimisée pour le traitement en rafale à faible latence.",
                        "Protection synproxy state dans Packet Filter (pf) : le pare-feu valide la poignée de main TCP avant de solliciter la passerelle C.",
                        "Bascule dynamique dans la table <bruteforce> dès dépassement de seuil (max-src-conn-rate) et priorité garantie aux IP de <partenaires_paiement>."
                    ]
                },
                blackbox_log: "[2026-11-14T11:30:51Z] [BLACKBOX][IMMUTABLE] [PF:SYNPROXY] Rafale détectée sur em0 (48 200 pkt/s) -> 312 IP ajoutées à <bruteforce> (block drop quick) | Latence table <partenaires_paiement> maintenue à 1.4 ms."
            },
            {
                id: "supply-chain-sshd",
                annee: "2024",
                cve: "CVE-2024-3094",
                categorie: "Supply Chain & Système",
                titre: "Type XZ Utils — Porte dérobée dans la chaîne logistique SSH",
                gravite: "Critique (CVSS 10.0)",
                resume: "Une bibliothèque de compression compromise par un acteur malveillant injecte du code caché dans le démon OpenSSH lié à systemd, permettant un accès administrateur furtif.",
                serveur_classique: {
                    titre: "Distribution Généraliste à dépendances multiples",
                    etapes: [
                        "Une mise à jour de paquet tiers introduit un objet binaire obfusqué dans une bibliothèque système.",
                        "Le démon sshd exposé publiquement charge la bibliothèque compromise au démarrage.",
                        "Une clé cryptographique spécifique permet à l'attaquant d'exécuter des commandes root avant même l'authentification."
                    ]
                },
                bouclier_raptor: {
                    titre: "Architecture CENTURION / RAPTOR-OS 2.0",
                    mecanismes: [
                        "Socle OpenBSD/amd64 pur : aucun systemd, aucune glibc ni chaîne de dépendances externes superflues.",
                        "Surface réseau externe fermée : le port SSH (22) est totalement bloqué sur l'interface publique em0 par pf.",
                        "Empreinte logicielle minimale auditée : seuls les composants essentiels au routage transactionnel sont actifs."
                    ]
                },
                blackbox_log: "[2026-11-14T14:18:09Z] [BLACKBOX][IMMUTABLE] [PF:DROP_SILENT] [INTERFACE:em0] [DST_PORT:22] Tentative de sonde SSH depuis 203.0.113.88 -> Démon sshd non exposé sur em0 | Zéro réponse émise."
            }
        ];
    }

    /**
     * 4. Génère dynamiquement les boutons de filtre par catégorie de menace.
     */
    function construireFiltresCategories() {
        const zoneFiltres = document.getElementById("pm-filters");
        if (!zoneFiltres) {
            return;
        }

        const categoriesUniques = ["Toutes"];
        etatModule.tousLesScenarios.forEach(function (sc) {
            if (categoriesUniques.indexOf(sc.categorie) === -1) {
                categoriesUniques.push(sc.categorie);
            }
        });

        zoneFiltres.innerHTML = categoriesUniques.map(function (cat) {
            const estActif = cat === etatModule.categorieActive ? " active" : "";
            return '<button type="button" class="pm-filter-btn' + estActif + '" data-cat="' + echapperHtml(cat) + '">' +
                echapperHtml(cat) +
                "</button>";
        }).join("");

        zoneFiltres.querySelectorAll(".pm-filter-btn").forEach(function (bouton) {
            bouton.addEventListener("click", function () {
                etatModule.categorieActive = this.getAttribute("data-cat");
                construireFiltresCategories();
                filtrerEtAfficher();
            });
        });
    }

    /**
     * 5. Filtre la liste selon la catégorie active et met à jour sélecteur + vue détaillée.
     */
    function filtrerEtAfficher() {
        const listeFiltree = etatModule.tousLesScenarios.filter(function (sc) {
            return etatModule.categorieActive === "Toutes" || sc.categorie === etatModule.categorieActive;
        });

        const compteur = document.getElementById("pm-counter");
        if (compteur) {
            compteur.textContent = listeFiltree.length + " scénario(s) analysé(s)";
        }

        if (listeFiltree.length === 0) {
            return;
        }

        const existeDansFiltre = listeFiltree.some(function (sc) {
            return sc.id === etatModule.scenarioActifId;
        });

        if (!existeDansFiltre) {
            etatModule.scenarioActifId = listeFiltree[0].id;
        }

        afficherSelecteurScenarios(listeFiltree);

        const scenarioCourant = listeFiltree.find(function (sc) {
            return sc.id === etatModule.scenarioActifId;
        });
        afficherDiagnosticScenario(scenarioCourant);
    }

    /**
     * 6. Affiche les cartes de sélection des attaques filtrées.
     */
    function afficherSelecteurScenarios(listeScenarios) {
        const zoneSelecteur = document.getElementById("pm-selector");
        if (!zoneSelecteur) {
            return;
        }

        zoneSelecteur.innerHTML = listeScenarios.map(function (sc) {
            const estSelectionne = sc.id === etatModule.scenarioActifId ? " selected" : "";
            return (
                '<button type="button" class="pm-card-btn' + estSelectionne + '" data-id="' + echapperHtml(sc.id) + '">' +
                    '<div class="pm-card-meta">' +
                        '<span class="pm-badge-cve">' + echapperHtml(sc.cve) + '</span>' +
                        '<span class="pm-badge-year">' + echapperHtml(sc.annee) + '</span>' +
                    '</div>' +
                    '<div class="pm-card-title">' + echapperHtml(sc.titre) + '</div>' +
                    '<div class="pm-card-cat">' + echapperHtml(sc.categorie) + '</div>' +
                '</button>'
            );
        }).join("");

        zoneSelecteur.querySelectorAll(".pm-card-btn").forEach(function (carte) {
            carte.addEventListener("click", function () {
                etatModule.scenarioActifId = this.getAttribute("data-id");
                filtrerEtAfficher();
            });
        });
    }

    /**
     * 7. Rend le comparatif complet (Serveur Classique vs Bouclier RAPTOR-OS + Blackbox).
     */
    function afficherDiagnosticScenario(scenario) {
        const conteneurVue = document.getElementById("pm-viewer");
        if (!conteneurVue || !scenario) {
            return;
        }

        const etapesClassiquesHtml = scenario.serveur_classique.etapes.map(function (etape) {
            return "<li>" + echapperHtml(etape) + "</li>";
        }).join("");

        const mecanismesRaptorHtml = scenario.bouclier_raptor.mecanismes.map(function (mec) {
            return "<li>" + echapperHtml(mec) + "</li>";
        }).join("");

        conteneurVue.innerHTML =
            '<article class="pm-report">' +
                '<header class="pm-report-header">' +
                    '<div class="pm-report-tags">' +
                        '<span class="pm-tag-cve">' + echapperHtml(scenario.cve) + ' (' + echapperHtml(scenario.annee) + ')</span>' +
                        '<span class="pm-tag-gravite">Gravité : ' + echapperHtml(scenario.gravite) + '</span>' +
                    '</div>' +
                    '<h2>' + echapperHtml(scenario.titre) + '</h2>' +
                    '<p class="pm-report-resume">' + echapperHtml(scenario.resume) + '</p>' +
                '</header>' +

                '<div class="pm-grid-compare">' +
                    '<section class="pm-panel pm-panel-danger">' +
                        '<h3>' + echapperHtml(scenario.serveur_classique.titre) + '</h3>' +
                        '<ol class="pm-list-steps">' + etapesClassiquesHtml + '</ol>' +
                    '</section>' +

                    '<section class="pm-panel pm-panel-shield">' +
                        '<h3>' + echapperHtml(scenario.bouclier_raptor.titre) + '</h3>' +
                        '<ul class="pm-list-shield">' + mecanismesRaptorHtml + '</ul>' +
                    '</section>' +
                '</div>' +

                '<section class="pm-blackbox">' +
                    '<div class="pm-blackbox-top">' +
                        '<span>JOURNAL IMMUABLE — /raptor_blackbox (append-only)</span>' +
                        '<button type="button" id="pm-copy-log" class="pm-copy-btn">Copier la trace</button>' +
                    '</div>' +
                    '<pre><code id="pm-log-content">' + echapperHtml(scenario.blackbox_log) + '</code></pre>' +
                '</section>' +
            '</article>';

        attacherCopieJournal();
    }

    /**
     * 8. Active le bouton de copie rapide du journal /raptor_blackbox.
     */
    function attacherCopieJournal() {
        const boutonCopie = document.getElementById("pm-copy-log");
        const blocLog = document.getElementById("pm-log-content");
        if (!boutonCopie || !blocLog) {
            return;
        }

        boutonCopie.addEventListener("click", function () {
            const texte = blocLog.textContent || "";
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(texte).then(function () {
                    boutonCopie.textContent = "Trace copiée ✓";
                    setTimeout(function () {
                        boutonCopie.textContent = "Copier la trace";
                    }, 2000);
                });
            }
        });
    }

    /**
     * 9. Assainit les chaînes de caractères contre toute injection XSS.
     */
    function echapperHtml(chaine) {
        return String(chaine)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    document.addEventListener("DOMContentLoaded", initialiserLaboratoire);
})();
