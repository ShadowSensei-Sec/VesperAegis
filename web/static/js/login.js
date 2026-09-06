document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("login-form");
    const changePasswordForm = document.getElementById("change-password-form");

    const usernameInput = document.getElementById("username");
    const passwordInput = document.getElementById("password");
    const loginButton = document.getElementById("login-button");
    const loginMessage = document.getElementById("login-message");

    const newUsernameInput = document.getElementById("new-username");
    const newPasswordInput = document.getElementById("new-password");
    const changePasswordButton = document.getElementById("change-password-button");
    const changePasswordMessage = document.getElementById("change-password-message");

    function showMessage(element, message, type = "error") {
        element.textContent = message;
        element.className = `login-message ${type}`;
    }

    function setButtonLoading(button, loading, normalText, loadingText) {
        button.disabled = loading;
        button.textContent = loading ? loadingText : normalText;
    }

    function showChangePasswordForm() {
        loginForm.classList.add("hidden");
        changePasswordForm.classList.remove("hidden");
    }

    loginButton.addEventListener("click", async () => {
        const username = usernameInput.value.trim();
        const password = passwordInput.value;

        if (!username || !password) {
            showMessage(
                loginMessage,
                "Please enter your username and password."
            );
            return;
        }

        setButtonLoading(
            loginButton,
            true,
            "Sign In",
            "Signing In..."
        );

        loginMessage.className = "login-message hidden";

        try {
            const response = await fetch("/api/auth/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                credentials: "same-origin",
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            });

            const data = await response.json();

            if (!response.ok) {
                showMessage(
                    loginMessage,
                    data.detail || "Invalid username or password."
                );
                return;
            }

            if (data.must_change_password) {
                showChangePasswordForm();
                return;
            }

            window.location.href = "/";
        } catch (error) {
            console.error("Login error:", error);

            showMessage(
                loginMessage,
                "Unable to connect to the authentication service."
            );
        } finally {
            setButtonLoading(
                loginButton,
                false,
                "Sign In",
                "Signing In..."
            );
        }
    });

    changePasswordButton.addEventListener("click", async () => {
        const username = newUsernameInput.value.trim();
        const password = newPasswordInput.value;

        if (!username || !password) {
            showMessage(
                changePasswordMessage,
                "Please enter a username and password."
            );
            return;
        }

        if (password.length < 8) {
            showMessage(
                changePasswordMessage,
                "Password must contain at least 8 characters."
            );
            return;
        }

        setButtonLoading(
            changePasswordButton,
            true,
            "Update Credentials",
            "Updating..."
        );

        changePasswordMessage.className = "login-message hidden";

        try {
            const response = await fetch(
                "/api/auth/change-credentials",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    credentials: "same-origin",
                    body: JSON.stringify({
                        username: username,
                        password: password
                    })
                }
            );

            const data = await response.json();

            if (!response.ok) {
                showMessage(
                    changePasswordMessage,
                    data.detail || "Unable to update credentials."
                );
                return;
            }

            showMessage(
                changePasswordMessage,
                "Credentials updated successfully. Redirecting...",
                "success"
            );

            setTimeout(() => {
                window.location.href = "/";
            }, 800);

        } catch (error) {
            console.error("Credential update error:", error);

            showMessage(
                changePasswordMessage,
                "Unable to connect to the authentication service."
            );
        } finally {
            setButtonLoading(
                changePasswordButton,
                false,
                "Update Credentials",
                "Updating..."
            );
        }
    });

    passwordInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            loginButton.click();
        }
    });

    newPasswordInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            changePasswordButton.click();
        }
    });
});