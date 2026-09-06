/* ============================================================
   VESPERAEGIS FIREWALL - SIDEBAR CONTROLLER
   ============================================================ */

document.addEventListener("DOMContentLoaded", () => {

    const sidebar = document.querySelector(".sidebar");

    /*
     * The sidebar uses the "sidebar" class,
     * not an element ID.
     */
    if (!sidebar) {
        return;
    }


    /*
     * Automatically highlight the current page.
     */
    const navigationLinks =
        sidebar.querySelectorAll(".nav-item");

    const currentPath =
        window.location.pathname;

    navigationLinks.forEach((link) => {

        const href = link.getAttribute("href");

        if (!href) {
            return;
        }

        if (
            href === currentPath ||
            (
                href !== "/" &&
                currentPath.startsWith(href)
            )
        ) {
            link.classList.add("active");
        } else {
            link.classList.remove("active");
        }
    });
});

    /*
     * Logout
     */
    const logoutButton =
        document.getElementById("logout-button");

    if (logoutButton) {
        logoutButton.addEventListener("click", async () => {

            logoutButton.disabled = true;
            logoutButton.querySelector(".nav-label").textContent =
                "Logging out...";

            try {
                const response = await fetch(
                    "/api/auth/logout",
                    {
                        method: "POST",
                        credentials: "same-origin"
                    }
                );

                if (response.ok) {
                    window.location.href = "/login";
                    return;
                }

                logoutButton.disabled = false;
                logoutButton.querySelector(".nav-label").textContent =
                    "Logout";

            } catch (error) {
                console.error("Logout error:", error);

                logoutButton.disabled = false;
                logoutButton.querySelector(".nav-label").textContent =
                    "Logout";
            }
        });
    }