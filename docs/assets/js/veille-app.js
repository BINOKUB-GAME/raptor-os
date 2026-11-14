/**
 * ============================================================================
 * NOM DU SCRIPT : assets/js/veille-app.js
 * NUMÉRO DE RÉVISION : Révision 1.0
 * ----------------------------------------------------------------------------
 * BLOC DESCRIPTIF DES INTÉGRATIONS :
 * Module autonome de gestion et d'affichage de la Veille Sécurité Hebdomadaire
 * pour CENTURION / RAPTOR-OS 2.0.
 * - Charge dynamiquement les billets depuis 'assets/data/veille.json'.
 * - Intègre un jeu de données de secours embarqué pour prévisualisation locale
 *   hors-ligne (protocole file:// sous Debian 13) sans blocage CORS.
 * - Met en valeur automatiquement le dernier billet publié dans l'encart
 *   'À la une cette semaine' (#veille-featured).
 * - Fournit un filtrage combiné par catégorie technique et par recherche libre.
 * ----------------------------------------------------------------------------
 * INDEX NUMÉROTÉ DES FONCTIONS :
 * 1. initialiserVeille()           : Point d'entrée principal au chargement du DOM.
 * 2. chargerBulletins()            : Récupère assets/data/veille.json ou active le repli.
 * 3. obtenirDonneesSecours()       : Retourne les billets embarqués pour test file://.
 * 4. afficherBulletinALaUne()      : Met en avant le bulletin hebdomadaire le plus récent.
 * 5. construireFiltresCategories() : Génère les boutons de filtre par thème technique.
 * 6. attacherRechercheTexte()      : Écoute la saisie dans le champ de recherche libre.
 * 7. filtrerEtAfficherArchives()   : Applique catégorie + mot-clé et rend la liste.
 * 8. echapperHtml()                : Assainit les chaînes contre toute injection XSS.
 * ============================================================================
 */

(function () {
    "use strict";

    /** État interne isolé du module Veille */
    const etatVeille = {
        tousLesBulletins: [],
        categorieActive: "Toutes",
        termeRecherche: ""
    };

    /**
     * 1. Point d'entrée principal au chargement du DOM.
     */
    function initialiserVeille() {
        const zoneArchives = document.getElementById("veille-list");
        if (!zoneArchives) {
            return;
        }
        chargerBulletins();
    }

    /**
     * 2. Récupère assets/data/veille.json via fetch() ou bascule sur le repli local.
     */
    async function chargerBulletins() {
        try {
            if (window.location.protocol === "file:") {
                etatVeille.tousLesBulletins = obtenirDonneesSecours();
            } else {
                const reponse = await fetch("assets/data/veille.json", { cache: "no-store" });
                if (!reponse.ok) {
                    throw new Error("Erreur HTTP " + reponse.status);
                }
                const donnees = await reponse.json();
                etatVeille.tousLesBulletins = Array.isArray(donnees.bulletins) ? donnees.bulletins : [];
            }
        } catch (erreur) {
            console.warn("[RAPTOR-OS Veille] Mode repli local activé :", erreur.message);
            etatVeille.tousLesBulletins = obtenirDonneesSecours();
        }

        if (etatVeille.tousLesBulletins.length > 0) {
            afficherBulletinALaUne(etatVeille.tousLesBulletins[0]);
            construireFiltresCategories();
            attacherRechercheTexte();
            filtrerEtAfficherArchives();
        }
    }

    /**
     * 3. Retourne les bulletins embarqués pour test local direct (file://).
     */
    function obtenirDonneesSecours() {
        return [
            {
                id: "2026-s46-synproxy-em0",
                semaine: "Semaine 46 — 2026",
                date: "2026-11-14",
                categorie: "Réseau & pf",
                titre: "Botnets IoT haute cadence : pourquoi le filtrage matériel Intel et synproxy deviennent indispensables",
                source_contexte: "Analyse des vagues de saturation TCP SYN ciblant les passerelles API financières au quatrième trimestre 2026.",
                resume: "Les campagnes DDoS applicatives et réseau utilisent désormais des rafales courtes mais très denses (plus de 40 000 paquets/seconde) pour épuiser les tables d'états des pare-feu logiciels classiques avant même que les systèmes de détection cloud ne réagissent.",
                eclairage_raptor: "Sur CENTURION / RAPTOR-OS 2.0, l'association d'un contrôleur Ethernet Intel dédié (em0) et de la directive 'synproxy state' dans Packet Filter (pf) absorbe les poignées de main TCP incomplètes directement au niveau du noyau OpenBSD, tout en réservant la bande passante prioritaire à la table <partenaires_paiement>."
            },
            {
                id: "2026-s45-openbsd80-confinement",
                semaine: "Semaine 45 — 2026",
                date: "2026-11-07",
                categorie: "OpenBSD & Noyau",
                titre: "OpenBSD 8.0 : le confinement natif (pledge & unveil) face aux vulnérabilités d'exécution de code",
                source_contexte: "Bilan technique des améliorations de réduction de surface d'attaque intégrées dans la branche OpenBSD 8.0 / amd64.",
                resume: "Alors que les environnements généralistes empilent des conteneurs et des agents de surveillance complexes pour tenter de contenir une intrusion après coup, le modèle OpenBSD restreint directement les appels système autorisés par chaque processus dès sa première milliseconde d'exécution.",
                eclairage_raptor: "Chaque passerelle compilée en C pur dans RAPTOR-OS 2.0 déclare strictement ses besoins via pledge(2) et verrouille son accès au disque avec unveil(2). Même face à une donnée malformée inédite, le noyau interrompt immédiatement le processus avant tout accès au système de fichiers ou au réseau sortant."
            },
            {
                id: "2026-s44-tracabilite-immuable",
                semaine: "Semaine 44 — 2026",
                date: "2026-10-31",
                categorie: "Paiements & Conformité",
                titre: "Intégrité des journaux d'audit : empêcher l'effacement des traces après incident",
                source_contexte: "Recommandations d'audit pour les infrastructures traitant des flux monétaires et journaux transactionnels.",
                resume: "Dans la majorité des incidents documentés en entreprise, la première action d'un intrus consiste à purger les journaux système et à désactiver les règles de pare-feu afin de masquer son passage pendant plusieurs semaines.",
                eclairage_raptor: "Avec le verrouillage noyau kern.securelevel=1 et l'attribut système append-only (sappnd / schg) appliqué sur /raptor_blackbox et /etc/pf.conf, même le compte root ne peut ni tronquer les preuves ni altérer le filtrage actif sans un redémarrage physique contrôlé."
            },
            {
                id: "2026-s43-bare-metal-vs-cloud",
                semaine: "Semaine 43 — 2026",
                date: "2026-10-24",
                categorie: "Matériel & Bare-Metal",
                titre: "Bastion Bare-Metal dédié vs VPS mutualisé : reprendre le contrôle physique de la couche matérielle",
                source_contexte: "Comparatif d'architecture pour les PME souhaitant isoler leur moteur de validation transactionnelle.",
                resume: "Héberger un composant critique de paiement sur une machine virtuelle mutualisée expose les flux sensibles aux voisins d'hyperviseur, aux failles spéculatives CPU et aux coupures d'API d'hébergeurs tiers.",
                eclairage_raptor: "Déployer RAPTOR-OS 2.0 sur une machine physique dédiée (bare-metal) équipée d'un SSD NVMe local et d'un lien Ethernet RJ-45 isolé élimine toute couche d'hyperviseur et garantit une latence déterministe sous charge."
            }
        ];
    }

    /**
     * 4. Met en avant le bulletin hebdomadaire le plus récent dans #veille-featured.
     */
    function afficherBulletinALaUne(bulletin) {
        const zoneUne = document.getElementById("veille-featured");
        if (!zoneUne || !bulletin) {
            return;
        }

        zoneUne.innerHTML =
            '<div class="vl-featured-card">' +
                '<div class="vl-featured-top">' +
                    '<span class="vl-pill-live">À LA UNE — ' + echapperHtml(bulletin.semaine) + '</span>' +
                    '<span class="vl-meta-date">Publié le ' + echapperHtml(bulletin.date) + ' · ' + echapperHtml(bulletin.categorie) + '</span>' +
                '</div>' +
                '<h2>' + echapperHtml(bulletin.titre) + '</h2>' +
                '<p class="vl-context">' + echapperHtml(bulletin.source_contexte) + '</p>' +
                '<p class="vl-summary">' + echapperHtml(bulletin.resume) + '</p>' +
                '<div class="vl-raptor-box">' +
                    '<strong>Éclairage CENTURION / RAPTOR-OS 2.0 :</strong> ' +
                    '<span>' + echapperHtml(bulletin.eclairage_raptor) + '</span>' +
                '</div>' +
            '</div>';
    }

    /**
     * 5. Génère dynamiquement les boutons de filtre par thème technique.
     */
    function construireFiltresCategories() {
        const zoneFiltres = document.getElementById("veille-filters");
        if (!zoneFiltres) {
            return;
        }

        const categories = ["Toutes"];
        etatVeille.tousLesBulletins.forEach(function (item) {
            if (categories.indexOf(item.categorie) === -1) {
                categories.push(item.categorie);
            }
        });

        zoneFiltres.innerHTML = categories.map(function (cat) {
            const classeActive = cat === etatVeille.categorieActive ? " active" : "";
            return '<button type="button" class="vl-filter-btn' + classeActive + '" data-cat="' + echapperHtml(cat) + '">' +
                echapperHtml(cat) +
                "</button>";
        }).join("");

        zoneFiltres.querySelectorAll(".vl-filter-btn").forEach(function (btn) {
            btn.addEventListener("click", function () {
                etatVeille.categorieActive = this.getAttribute("data-cat");
                construireFiltresCategories();
                filtrerEtAfficherArchives();
            });
        });
    }

    /**
     * 6. Écoute la saisie dans le champ de recherche libre.
     */
    function attacherRechercheTexte() {
        const champRecherche = document.getElementById("veille-search");
        if (!champRecherche) {
            return;
        }

        champRecherche.addEventListener("input", function () {
            etatVeille.termeRecherche = this.value.trim().toLowerCase();
            filtrerEtAfficherArchives();
        });
    }

    /**
     * 7. Applique le filtre de catégorie + recherche texte et rend les bulletins.
     */
    function filtrerEtAfficherArchives() {
        const zoneListe = document.getElementById("veille-list");
        const compteur = document.getElementById("veille-counter");
        if (!zoneListe) {
            return;
        }

        const resultats = etatVeille.tousLesBulletins.filter(function (item) {
            const matchCat = etatVeille.categorieActive === "Toutes" || item.categorie === etatVeille.categorieActive;
            if (!matchCat) {
                return false;
            }
            if (!etatVeille.termeRecherche) {
                return true;
            }
            const texteGlobal = (
                item.titre + " " +
                item.resume + " " +
                item.eclairage_raptor + " " +
                item.categorie + " " +
                item.semaine
            ).toLowerCase();
            return texteGlobal.indexOf(etatVeille.termeRecherche) !== -1;
        });

        if (compteur) {
            compteur.textContent = resultats.length + " bulletin(s) affiché(s)";
        }

        if (resultats.length === 0) {
            zoneListe.innerHTML = '<div class="vl-empty">Aucun bulletin ne correspond à votre recherche.</div>';
            return;
        }

        zoneListe.innerHTML = resultats.map(function (item) {
            return (
                '<article class="vl-article-card">' +
                    '<div class="vl-article-header">' +
                        '<span class="vl-badge-week">' + echapperHtml(item.semaine) + ' (' + echapperHtml(item.date) + ')</span>' +
                        '<span class="vl-badge-cat">' + echapperHtml(item.categorie) + '</span>' +
                    '</div>' +
                    '<h3>' + echapperHtml(item.titre) + '</h3>' +
                    '<p class="vl-article-summary">' + echapperHtml(item.resume) + '</p>' +
                    '<div class="vl-raptor-box">' +
                        '<strong>Réponse RAPTOR-OS 2.0 :</strong> ' +
                        '<span>' + echapperHtml(item.eclairage_raptor) + '</span>' +
                    '</div>' +
                '</article>'
            );
        }).join("");
    }

    /**
     * 8. Assainit les chaînes de caractères contre toute injection XSS.
     */
    function echapperHtml(chaine) {
        return String(chaine)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    document.addEventListener("DOMContentLoaded", initialiserVeille);
})();
