/* ============================================================================
 * FICHIER     : docs/assets/js/man-filter.js
 * REVISION    : 1.0
 * DESCRIPTION : Moteur de recherche et filtrage temps reel pour la page de
 *               manuel unifiee centurion(8) (docs/man.html) fusionnant rap
 *               et Packet Filter (pf) sous RAPTOR-OS 2.0. Aucune dependance
 *               externe requise.
 *
 * FONCTIONS NUMEROTEES :
 *   01. initManFilter       - Initialise les ecouteurs sur recherche et filtres
 *   02. normalizeText       - Normalise une chaine (minuscules, sans accents)
 *   03. applyManFilters     - Filtre les entrees .man-entry et met a jour le compteur
 *   04. bindShortcutKeys    - Active le raccourci '/' (style less/man) et Echap
 * ============================================================================ */

(function () {
    "use strict";

    let activeCategory = "all";

    /* 02. Normalise une chaine (minuscules, sans accents) */
    function normalizeText(str) {
        return (str || "")
            .toLowerCase()
            .normalize("NFD")
            .replace(/[\u0300-\u036f]/g, "");
    }

    /* 03. Filtre les entrees .man-entry et met a jour le compteur */
    function applyManFilters() {
        const input = document.getElementById("man-search");
        const counter = document.getElementById("man-count");
        const entries = document.querySelectorAll(".man-entry");
        const sections = document.querySelectorAll(".man-section[data-filterable='true']");

        const query = normalizeText(input ? input.value.trim() : "");
        let visibleCount = 0;

        entries.forEach(function (entry) {
            const category = entry.getAttribute("data-category") || "all";
            const content = normalizeText(entry.textContent);

            const matchCategory = (activeCategory === "all") || (category === activeCategory);
            const matchQuery = (query === "") || (content.indexOf(query) !== -1);

            if (matchCategory && matchQuery) {
                entry.classList.remove("is-hidden");
                visibleCount++;
            } else {
                entry.classList.add("is-hidden");
            }
        });

        sections.forEach(function (sec) {
            const visibleInSec = sec.querySelectorAll(".man-entry:not(.is-hidden)").length;
            if (visibleInSec === 0) {
                sec.classList.add("is-hidden");
            } else {
                sec.classList.remove("is-hidden");
            }
        });

        if (counter) {
            counter.textContent = visibleCount + " entrée(s) affichée(s)";
        }
    }

    /* 04. Active le raccourci '/' (style less/man) et Echap */
    function bindShortcutKeys(searchInput) {
        document.addEventListener("keydown", function (event) {
            if (!searchInput) {
                return;
            }
            if (event.key === "/" && document.activeElement !== searchInput) {
                event.preventDefault();
                searchInput.focus();
                searchInput.select();
            } else if (event.key === "Escape" && document.activeElement === searchInput) {
                searchInput.value = "";
                applyManFilters();
                searchInput.blur();
            }
        });
    }

    /* 01. Initialise les ecouteurs sur recherche et filtres */
    function initManFilter() {
        const searchInput = document.getElementById("man-search");
        const filterButtons = document.querySelectorAll(".filter-btn");

        if (searchInput) {
            searchInput.addEventListener("input", applyManFilters);
            bindShortcutKeys(searchInput);
        }

        filterButtons.forEach(function (btn) {
            btn.addEventListener("click", function () {
                filterButtons.forEach(function (b) {
                    b.classList.remove("active");
                });
                btn.classList.add("active");
                activeCategory = btn.getAttribute("data-filter") || "all";
                applyManFilters();
            });
        });

        applyManFilters();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initManFilter);
    } else {
        initManFilter();
    }
})();
