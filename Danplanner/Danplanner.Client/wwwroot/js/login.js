$(function () {
    const loginModalEl = document.getElementById('loginModal');
    const loginModal = new bootstrap.Modal(loginModalEl);

    // OPEN MODAL ON LOGIN BUTTON CLICK
    $("#loginBtn").on("click", function (e) {
        e.preventDefault();

        const identifier = $("#loginIdentifier").val().trim();

        if (!identifier) {
            alert("Enter Email");
            return;
        }

        if (identifier.includes("@")) {
            // USER → REQUEST OTP
            $.ajax({
                type: "POST",
                url: "/api/auth/user/request-code",
                contentType: "application/json",
                data: JSON.stringify({ UserEmail: identifier }),
                success: function () {
                    $("#userOtpGroup").show();
                    $("#adminPasswordGroup").hide();
                    $("#loginCode").val("").focus();
                    loginModal.show();
                    alert("OTP er sendt til din email.");
                },
                error: function (xhr) {
                    if (xhr.status === 404) {
                        alert("Denne email er ikke registreret. Brug 'Registrer'-knappen først.");
                    } else {
                        alert("Kunne ikke sende OTP. Prøv igen senere.");
                    }
                }
            });
        } else {
            //VALIDATE ADMIN ID BEFORE SHOWING MODAL
            const adminId = parseInt(identifier, 10);

            if (isNaN(adminId)) {
                alert("Ugyldigt ID.");
                return;
            }

            $.ajax({
                type: "POST",
                url: "/api/auth/admin/check-id",
                contentType: "application/json",
                data: JSON.stringify({ AdminId: adminId }),
                success: function () {
                    // VALID ADMIN → show admin password input
                    $("#adminPasswordGroup").show();
                    $("#userOtpGroup").hide();
                    $("#loginPassword").val("").focus();
                    loginModal.show();
                },
                error: function (xhr) {
                    if (xhr.status === 404) {
                        alert("Indtast venligst en gyldig email.");
                    } else {
                        alert("Kunne ikke verificere Admin ID. Prøv igen.");
                    }
                }
            });
        }

    });

    // LOGIN BUTTON I MODAL (EVENT DELEGATION)
    $(document).on("click", "#loginSubmitBtn", function (e) {
        e.preventDefault();

        const identifier = $("#loginIdentifier").val().trim();
        const password = $("#loginPassword").val().trim();
        const otp = $("#loginCode").val().trim();


        if (!identifier) {
            alert("Enter Email or Admin ID.");
            return;
        }

        // USER LOGIN → VERIFY OTP
        if (identifier.includes("@")) {
            if (!otp) {
                alert("Enter the OTP code sent to your email.");
                return;
            }

            $.ajax({
                type: "POST",
                url: "/api/auth/user/verify-code",
                contentType: "application/json",
                data: JSON.stringify({
                    UserEmail: identifier,
                    Code: otp
                }),
                success: function () {
                    loginModal.hide();
                    location.reload();
                },
                error: function (xhr) {
                    alert(xhr.responseText || "Incorrect OTP.");
                }
            });
        }
            // ADMIN LOGIN → ID & PASSWORD
        else {
            const adminId = parseInt(identifier, 10);
            if (isNaN(adminId) || !password) {
                alert("Enter Admin ID and password.");
                return;
            }


            $.ajax({
                type: "POST",
                url: "/api/auth/login",
                contentType: "application/json",
                data: JSON.stringify({
                    AdminId: adminId,
                    Password: password
                }),
                success: function (resp) {
                    loginModal.hide();
                    location.reload();
                },
                error: function (xhr) {
                    alert(xhr.responseText || "Admin login failed.");
                }
            });
        }
    });

    // LOGOUT
    $(document).on("click", "#logoutBtn", function () {
        $.ajax({
            type: "POST",
            url: "/api/auth/logout",
            success: function () {
                location.href = "/";
            },
            error: function () {
                alert("Logout failed.");
            }
        });
    });
});
