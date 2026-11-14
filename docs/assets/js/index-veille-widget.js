/**
 * ============================================================================
 * NOM DU SCRIPT : assets/js/index-veille-widget.js
 * NUMÉRO DE RÉVISION : Révision 1.0
 * ----------------------------------------------------------------------------
 * BLOC DESCRIPTIF DES INTÉGRATIONS :
 * Module autonome léger destiné à la page d'accueil (docs/index.html).
 * - Lit 'assets/data/veille.json' pour afficher dynamiquement le titre,
 *   la semaine et le résumé du bulletin de sécurité le plus récent dans la
 *   carte Veille de l'accueil.
 * - Intègre un repli local hors-ligne (protocole file://) pour prévisualisation
 *   directe sans erreur dans le navigateur.
 * ----------------------------------------------------------------------------
 * INDEX NUMÉROTÉ DES FONCTIONS :
 * 1. initialiserWidgetVeilleAccueil() : Point d'entrée au chargement du DOM.
 * 2. chargerDernierBulletin()         : Récupère le premier billet de veille.json.
 * 3. afficherApercuBulletin()         : Injecte le titre et le résumé dans la carte.
 * ============================================================================
 */

(function () {
    "use strict";

    /**
     * 1. Point d'entrée principal au chargement du DOM.
     */
    function initialiserWidgetVeilleAccueil() {
        const conteneurTitre = document.getElementById("home-veille-title");
        if (!conteneurTitre) {
            return;
        }
        chargerDernierBulletin();
    }

    /**
     * 2. Récupère le bulletin le plus récent depuis assets/data/veille.json.
     */
    async function chargerDernierBulletin() {
        const bulletinSecours = {
            semaine: "Semaine 46 — 2026",
            categorie: "Réseau & pf",
            titre: "Botnets IoT haute cadence : filtrage matériel Intel et synproxy",
            resume: "Comment l'association d'une interface Intel em0 dédiée et de synproxy dans Packet Filter absorbe les rafales TCP SYN avant toute saturation."
        };

        try {
            if (window.location.protocol === "file:") {
                afficherApercuBulletin(bulletinSecours);
                return;
            }

            const reponse = await fetch("assets/data/veille.json", { cache: "no-store" });
            if (!reponse.ok) {
                throw new Error("HTTP " + reponse.status);
            }

            const donnees = await reponse.json();
            if (Array.isArray(donnees.bulletins) && donnees.bulletins.length > 0) {
                afficherApercuBulletin(donnees.bulletins[0]);
            } else {
                afficherApercuBulletin(bulletinSecours);
            }
        } catch (erreur) {
            afficherApercuBulletin(bulletinSecours);
        }
    }

    /**
     * 3. Injecte de manière sécurisée (textContent) les informations du bulletin.
     */
    function afficherApercuBulletin(bulletin) {
        const elBadge = document.getElementById("home-veille-badge");
        const elTitre = document.getElementById("home-veille-title");
        const elResume = document.getElementById("home-veille-summary");

        if (elBadge && bulletin.semaine) {
            elBadge.textContent = "VEILLE HEBDO • " + bulletin.semaine.toUpperCase();
        }
        if (elTitre && bulletin.titre) {
            elTitre.textContent = bulletin.titre;
        }
        if (elResume && bulletin.resume) {
            elResume.textContent = bulletin.resume;
        }
    }

    document.addEventListener("DOMContentLoaded", initialiserWidgetVeilleAccueil);
})();
