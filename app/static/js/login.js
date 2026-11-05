document.addEventListener("DOMContentLoaded", () => {
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");

    document.querySelectorAll("[data-demo-email][data-demo-password]").forEach((button) => {
        button.addEventListener("click", () => {
            emailInput.value = button.dataset.demoEmail;
            passwordInput.value = button.dataset.demoPassword;
        });
    });
});