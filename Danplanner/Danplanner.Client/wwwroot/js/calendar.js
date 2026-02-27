document.addEventListener("DOMContentLoaded", function () {
    if (typeof flatpickr === "undefined") {
        console.warn("flatpickr not found. Include flatpickr scripts in _Layout.cshtml.");
        return;
    }

    const daLocale = (flatpickr && flatpickr.l10ns && flatpickr.l10ns.da) ? flatpickr.l10ns.da : null;

    const startSpan = document.getElementById("start");
    const endSpan = document.getElementById("end");
    const daysSpan = document.getElementById("days");
    const clearBtn = document.getElementById("clearSelection");

    const calcDays = (a, b) => {
        if (!a || !b) return 0;
        const ms = b.setHours(0, 0, 0, 0) - a.setHours(0, 0, 0, 0);
        return Math.max(0, Math.round(ms / (1000 * 60 * 60 * 24)));
    };

    const format = (instance, date) => {
        if (!date) return "—";
        return instance.formatDate(date, "d. M.");
    };

    const fp = flatpickr("#fp-calendar", {
        locale: daLocale || "default",
        inline: true,
        mode: "range",
        showMonths: 2,
        minDate: "today",
        dateFormat: "d-m-Y",
        weekNumbers: true,
        onChange: function (selectedDates, dateStr, instance) {
            if (!selectedDates || selectedDates.length === 0) {
                startSpan.textContent = "—";
                endSpan.textContent = "—";
                daysSpan.textContent = "0";
                return;
            }

            if (selectedDates.length === 1) {
                startSpan.textContent = format(instance, selectedDates[0]);
                endSpan.textContent = "—";
                daysSpan.textContent = "0";
                return;
            }

            // two dates
            const start = selectedDates[0];
            const end = selectedDates[1];
            startSpan.textContent = format(instance, start);
            endSpan.textContent = format(instance, end);
            daysSpan.textContent = calcDays(new Date(start), new Date(end));
        },
        onReady: function (_, __, instance) {
        }
    });

    if (clearBtn) {
        clearBtn.addEventListener("click", function () {
            fp.clear();
            startSpan.textContent = "—";
            endSpan.textContent = "—";
            daysSpan.textContent = "0";
        });
    }
});