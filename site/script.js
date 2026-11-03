"use strict";

const status = document.getElementById("copy-status");

if (navigator.clipboard && window.isSecureContext) {
  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.hidden = false;
    button.addEventListener("click", async () => {
      const source = document.getElementById(button.dataset.copy);
      if (!source) return;
      try {
        await navigator.clipboard.writeText(source.textContent);
        status.textContent = button.dataset.copy === "install-command"
          ? "Install command copied."
          : "Code copied.";
      } catch {
        status.textContent = "Select the command or code to copy it manually.";
      }
    });
  });
}
