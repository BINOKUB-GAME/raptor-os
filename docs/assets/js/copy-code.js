/* ============================================================================
 * FICHIER     : docs/assets/js/copy-code.js
 * REVISION    : 1.0
 * DESCRIPTION : Module autonome de copie en un clic pour les blocs de code
 *               (.terminal-block) et empreintes (.sha-box) du site CENTURION
 *               (RAPTOR-OS 2.0). Retire automatiquement les invites shell
 *               (.prompt), assure une ergonomie tactile mobile/bureau et
 *               integre un repli compatible HTTPS et file://.
 *
 * FONCTIONS NUMEROTEES :
 *   01. initCopyButtons     - Injecte les boutons Copier sur les blocs cibles
 *   02. extractCleanText    - Extrait le texte utile sans les invites .prompt
 *   03. copyToClipboard     - Copie via Clipboard API avec repli textarea
 *   04. triggerButtonState  - Affiche le retour visuel temporaire "Copie !"
 * ============================================================================ */

(function () {
    "use strict";

    /* 02. Extrait le texte utile sans les invites .prompt */
    function extractCleanText(container) {
        const clone = container.cloneNode(true);
        const existingBtn = clone.querySelector(".copy-btn");
        if (existingBtn) {
            existingBtn.remove();
        }
        const prompts = clone.querySelectorAll(".prompt");
        prompts.forEach(function (p) {
            p.remove();
        });
        return (clone.textContent || "").trim();
    }

    /* 03. Copie via Clipboard API avec repli textarea */
    function copyToClipboard(text, onSuccess) {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(onSuccess).catch(function () {
                fallbackCopy(text, onSuccess);
            });
        } else {
            fallbackCopy(text, onSuccess);
        }
    }

    function fallbackCopy(text, onSuccess) {
        const area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        try {
            if (document.execCommand("copy")) {
                onSuccess();
            }
        } catch (err) {
            /* Echec silencieux si bloque par le navigateur */
        }
        document.body.removeChild(area);
    }

    /* 04. Affiche le retour visuel temporaire "Copie !" */
    function triggerButtonState(btn) {
        const originalLabel = btn.getAttribute("data-label") || "Copier";
        btn.textContent = "Copié !";
        btn.classList.add("is-copied");
        window.setTimeout(function () {
            btn.textContent = originalLabel;
            btn.classList.remove("is-copied");
        }, 1800);
    }

    /* 01. Injecte les boutons Copier sur les blocs cibles */
    function initCopyButtons() {
        const targets = document.querySelectorAll(".terminal-block, .sha-box");
        targets.forEach(function (block) {
            if (block.querySelector(".copy-btn")) {
                return;
            }
            block.classList.add("has-copy-btn");

            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = "copy-btn";
            btn.textContent = "Copier";
            btn.setAttribute("data-label", "Copier");
            btn.setAttribute("aria-label", "Copier ce bloc dans le presse-papiers");

            btn.addEventListener("click", function () {
                const payload = extractCleanText(block);
                copyToClipboard(payload, function () {
                    triggerButtonState(btn);
                });
            });

            block.appendChild(btn);
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initCopyButtons);
    } else {
        initCopyButtons();
    }
})();
