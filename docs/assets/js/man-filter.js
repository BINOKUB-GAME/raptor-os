/**
 * ============================================================================
 * NOM DU SCRIPT : assets/js/man-filter.js
 * NUMÉRO DE RÉVISION : Révision 2.2
 * ----------------------------------------------------------------------------
 * BLOC DESCRIPTIF DES INTÉGRATIONS :
 * Moteur de recherche et de filtrage visuel haute lisibilité pour le manuel
 * système centurion(8) (docs/man.html) de CENTURION / RAPTOR-OS 2.0.
 * - Encapsule chaque résultat trouvé lors d'une recherche ou d'un filtre dans
 *   une boîte gris foncé délimitée (.man-search-card) pour le détacher
 *   visuellement du fond blanc du manuel.
 * - Surligne sans risque XSS (parcours des nœuds texte DOM) les occurrences du
 *   terme recherché à l'intérieur des boîtes de résultats.
 * - Masque temporairement les sections statiques non filtrables (SYNOPSIS,
 *   EXEMPLES, FILES, SEE ALSO) lorsqu'un mot-clé est saisi afin d'éviter
 *   toute confusion visuelle sous les résultats.
 * ----------------------------------------------------------------------------
 * INDEX NUMÉROTÉ DES FONCTIONS :
 * 1. initialiserFiltreManuel()     : Point d'entrée au chargement du DOM.
 * 2. attacherEvenements()          : Relie saisie, filtres et raccourcis clavier.
 * 3. appliquerFiltres()            : Filtre les entrées, gère les boîtes et sections.
 * 4. definirVisibiliteElement()    : Applique ou retire le masquage CSS prioritaire.
 * 5. nettoyerSurlignage()          : Supprime les balises <mark> précédentes.
 * 6. surlignerTermeDansElement()   : Met en valeur le mot recherché dans la boîte.
 * 7. normaliserTexte()             : Normalise une chaîne (sans accents/majuscules).
 * ============================================================================
 */

(function () {
    "use strict";

    let categorieActive = "all";

    /**
     * 1. Point d'entrée principal au chargement du DOM.
     */
    function initialiserFiltreManuel() {
        const champRecherche = document.getElementById("man-search");
        const compteur = document.getElementById("man-count");

        if (!champRecherche || !compteur) {
            return;
        }

        attacherEvenements(champRecherche);
        appliquerFiltres();
    }

    /**
     * 2. Relie le champ de recherche, les boutons de catégories et le clavier.
     */
    function attacherEvenements(champRecherche) {
        champRecherche.addEventListener("input", appliquerFiltres);

        document.querySelectorAll(".filter-btn").forEach(function (bouton) {
            bouton.addEventListener("click", function () {
                document.querySelectorAll(".filter-btn").forEach(function (b) {
                    b.classList.remove("active");
                });
                this.classList.add("active");
                categorieActive = this.getAttribute("data-filter") || "all";
                appliquerFiltres();
            });
        });

        document.addEventListener("keydown", function (evenement) {
            const cible = evenement.target;
            const estDansChamp = cible && (cible.tagName === "INPUT" || cible.tagName === "TEXTAREA");

            if (evenement.key === "/" && !estDansChamp) {
                evenement.preventDefault();
                champRecherche.focus();
                champRecherche.select();
            } else if (evenement.key === "Escape" && document.activeElement === champRecherche) {
                champRecherche.value = "";
                appliquerFiltres();
            }
        });
    }

    /**
     * 3. Filtre chaque .man-entry, applique le style boîte gris foncé et gère les sections.
     */
    function appliquerFiltres() {
        const champRecherche = document.getElementById("man-search");
        const compteur = document.getElementById("man-count");
        const saisieBrute = champRecherche ? champRecherche.value.trim() : "";
        const terme = normaliserTexte(saisieBrute);
        const estEnRechercheOuFiltre = (terme !== "" || categorieActive !== "all");

        const toutesLesEntrees = document.querySelectorAll(".man-entry");
        const totalEntrees = toutesLesEntrees.length;
        let visibles = 0;

        toutesLesEntrees.forEach(function (entree) {
            nettoyerSurlignage(entree);

            const categorieEntree = entree.getAttribute("data-category") || "";
            const texteEntree = normaliserTexte(entree.textContent || "");

            const correspondCategorie = (categorieActive === "all" || categorieEntree === categorieActive);
            const correspondTexte = (terme === "" || texteEntree.indexOf(terme) !== -1);
            const estVisible = correspondCategorie && correspondTexte;

            definirVisibiliteElement(entree, estVisible);

            if (estVisible) {
                visibles += 1;
                if (estEnRechercheOuFiltre) {
                    entree.classList.add("man-search-card");
                    if (terme !== "") {
                        surlignerTermeDansElement(entree, terme);
                    }
                } else {
                    entree.classList.remove("man-search-card");
                }
            } else {
                entree.classList.remove("man-search-card");
            }
        });

        /* Masque les sections filtrables qui ne contiennent aucun résultat */
        document.querySelectorAll('.man-section[data-filterable="true"]').forEach(function (section) {
            const entreesSection = section.querySelectorAll(".man-entry");
            let sectionAUnVisible = false;

            entreesSection.forEach(function (entree) {
                if (!entree.classList.contains("man-hidden")) {
                    sectionAUnVisible = true;
                }
            });

            definirVisibiliteElement(section, sectionAUnVisible);
        });

        /* Masque temporairement les sections statiques (SYNOPSIS, EXEMPLES, FILES...) lors d'une saisie */
        document.querySelectorAll('.man-section:not([data-filterable="true"])').forEach(function (sectionStatique) {
            definirVisibiliteElement(sectionStatique, terme === "");
        });

        if (compteur) {
            compteur.textContent = visibles + " / " + totalEntrees + " entrée" + (visibles > 1 ? "s" : "") + " affichée" + (visibles > 1 ? "s" : "");
        }
    }

    /**
     * 4. Applique ou retire le masquage CSS prioritaire sur un élément du DOM.
     */
    function definirVisibiliteElement(element, estVisible) {
        if (estVisible) {
            element.classList.remove("man-hidden");
            element.removeAttribute("hidden");
            element.style.removeProperty("display");
        } else {
            element.classList.add("man-hidden");
            element.setAttribute("hidden", "hidden");
            element.style.setProperty("display", "none", "important");
        }
    }

    /**
     * 5. Retire proprement toutes les balises <mark class="man-highlight"> existantes.
     */
    function nettoyerSurlignage(conteneur) {
        const marques = conteneur.querySelectorAll("mark.man-highlight");
        marques.forEach(function (marque) {
            const noeudTexte = document.createTextNode(marque.textContent || "");
            if (marque.parentNode) {
                marque.parentNode.replaceChild(noeudTexte, marque);
            }
        });
        conteneur.normalize();
    }

    /**
     * 6. Surligne les occurrences du terme dans les nœuds texte sans altérer le HTML.
     */
    function surlignerTermeDansElement(conteneur, termeNormalise) {
        if (!termeNormalise) {
            return;
        }

        const walker = document.createTreeWalker(conteneur, NodeFilter.SHOW_TEXT, null);
        const noeudsATraiter = [];
        let noeudCourant = walker.nextNode();

        while (noeudCourant) {
            if (noeudCourant.nodeValue && noeudCourant.nodeValue.trim() !== "") {
                noeudsATraiter.push(noeudCourant);
            }
            noeudCourant = walker.nextNode();
        }

        noeudsATraiter.forEach(function (noeudTexte) {
            const texteOriginal = noeudTexte.nodeValue;
            const texteNormalise = normaliserTexte(texteOriginal);
            let indexTrouve = texteNormalise.indexOf(termeNormalise);

            if (indexTrouve === -1 || !noeudTexte.parentNode) {
                return;
            }

            const fragment = document.createDocumentFragment();
            let curseur = 0;

            while (indexTrouve !== -1) {
                if (indexTrouve > curseur) {
                    fragment.appendChild(document.createTextNode(texteOriginal.slice(curseur, indexTrouve)));
                }

                const marque = document.createElement("mark");
                marque.className = "man-highlight";
                marque.textContent = texteOriginal.slice(indexTrouve, indexTrouve + termeNormalise.length);
                fragment.appendChild(marque);

                curseur = indexTrouve + termeNormalise.length;
                indexTrouve = texteNormalise.indexOf(termeNormalise, curseur);
            }

            if (curseur < texteOriginal.length) {
                fragment.appendChild(document.createTextNode(texteOriginal.slice(curseur)));
            }

            noeudTexte.parentNode.replaceChild(fragment, noeudTexte);
        });
    }

    /**
     * 7. Normalise une chaîne (minuscules, sans accents).
     */
    function normaliserTexte(chaine) {
        return String(chaine)
            .toLowerCase()
            .normalize("NFD")
            .replace(/[\u0300-\u036f]/g, "")
            .trim();
    }

    document.addEventListener("DOMContentLoaded", initialiserFiltreManuel);
})();
