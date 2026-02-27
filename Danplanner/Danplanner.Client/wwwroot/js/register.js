$(function () {
    const registerModalEl = document.getElementById('registerModal');
    const registerModal = new bootstrap.Modal(registerModalEl);

    let verifiedEmail = ""; // Gemmer email efter OTP-verifikation

    // Åbn modal kun hvis navbar email er udfyldt
    $("#registerBtn").click(function (e) {
        e.preventDefault();
        const email = $("#loginIdentifier").val().trim();

        if (!email) {
            alert("Indtast venligst din email i topbaren før registrering.");
            return;
        }

        // Sæt email i OTP sektionen
        $("#otpEmail").val(email);

        // Reset modal UI
        $("#otpSection").show();
        $("#verifyOtpArea").hide();
        $("#registerForm").hide();

        registerModal.show();
    });

    // -------------------------------
    // SEND OTP
    // -------------------------------
    $("#sendOtpBtn").click(function (e) {
        e.preventDefault();
        const email = $("#otpEmail").val().trim();
        if (!email) {
            alert("Indtast en email.");
            return;
        }

        $.ajax({
            url: "/api/auth/user/request-register-code",
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify({ UserEmail: email }),
            success: function () {
                alert("OTP sendt til din email.");
                $("#verifyOtpArea").show();
            },
            error: function (xhr) {
                console.error("Send OTP error:", xhr);
                alert("Kunne ikke sende OTP.");
            }
        });
    });

    // -------------------------------
    // VERIFY OTP
    // -------------------------------
    $("#verifyOtpBtn").click(function (e) {
        e.preventDefault();
        const email = $("#otpEmail").val().trim();
        const code = $("#otpCode").val().trim();

        if (!code) {
            alert("Indtast OTP kode.");
            return;
        }

        $.ajax({
            url: "/api/auth/user/verify-register-code",
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify({ UserEmail: email, Code: code }),
            success: function () {
                alert("OTP verificeret! Du kan nu færdiggøre registreringen.");

                // Gem emailen, så registreringsformularen bruger den
                verifiedEmail = email;

                $("#otpSection").hide();
                $("#registerForm").show();

                // Sæt emailen i formularen (readonly)
                if ($("#registerForm #registerEmail").length === 0) {
                    $("#registerForm").prepend(`
                        <div class="mb-3">
                            <label class="form-label">Email</label>
                            <input type="email" id="registerEmail" class="form-control" value="${verifiedEmail}" readonly>
                        </div>
                    `);
                } else {
                    $("#registerEmail").val(verifiedEmail);
                }
            },
            error: function (xhr) {
                console.error("Verify OTP error:", xhr);
                alert("Forkert eller udløbet OTP.");
            }
        });
    });

    // -------------------------------
    // FINAL REGISTRATION
    // -------------------------------
    $("#registerForm").submit(function (e) {
        e.preventDefault();

        const user = {
            UserName: $("#registerUsername").val().trim(),
            UserEmail: verifiedEmail, // Brug den verificerede email
            UserMobile: $("#registerMobile").val().trim(),
            UserAdress: $("#registerAddress").val().trim()
        };

        $.ajax({
            url: "/api/auth/user/register-user",
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify(user),
            success: function () {
                alert("Bruger oprettet!");
                location.reload();
            },
            error: function (xhr) {
                console.error("Register user error:", xhr);
                alert("Registrering fejlede.");
            }
        });
    });
});
