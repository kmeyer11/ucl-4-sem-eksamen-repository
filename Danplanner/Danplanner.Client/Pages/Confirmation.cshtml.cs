using Danplanner.Application.Interfaces.AccommodationInterfaces;
using Danplanner.Application.Interfaces.AddonInterfaces;
using Danplanner.Application.Interfaces.BookingInterfaces;
using Danplanner.Application.Interfaces.ConfirmationInterfaces;
using Danplanner.Application.Interfaces.UserInterfaces;
using Danplanner.Application.Models;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Application.Services;
using Danplanner.Domain.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using Danplanner.Application.Interfaces.SeasonInterfaces;
using Danplanner.Application.Interfaces.ReservationInterfaces;

namespace Danplanner.Client.Pages
{
    public class ConfirmationModel : PageModel
    {
        private readonly IAddonGetAll _addonGetAll;
        private readonly IAccommodationTransfer _accommodationService;
        private readonly IAccommodationUpdate _availabilityService;
        private readonly IWebHostEnvironment _env;
        private readonly IBookingAdd _bookingAdd;
        private readonly IUserAdd _userAdd;
        private readonly IUserGetByEmail _userGetByEmail;
        private readonly IUserGetById _userGetById;
        private readonly IAccommodationGetAll _accommodationGetAll;
        private readonly IAccommodationConverter _accommodationConverter;
        private readonly IAddressService _addressService;
        private readonly IOrderPricing _priceCalculator;
        private readonly IParseDate _parseDate;
        private readonly ISeasonGetForDate _getSeasonForDate;
        private readonly IBookingNotificationService _notificationService;
        private readonly IReservationLockService _reservationLockService;
        public ContactInformation ContactInformation { get; set; }

        public ConfirmationModel
        (
            IAddonGetAll addonGetAll,
            IAccommodationTransfer accommodationService,
            IAccommodationUpdate availabilityService, 
            IWebHostEnvironment env, 
            IBookingAdd bookingAdd, 
            IUserAdd userAdd, 
            IUserGetByEmail userGetByEmail, 
            IUserGetById userGetById,
            IAccommodationGetAll accommodationGetAll, 
            IAccommodationConverter accommodationConverter,
            IAddressService addressService,
            IOrderPricing calculateTotalPrice, 
            IParseDate parseDate,
            ISeasonGetForDate getSeasonForDate,
            IBookingNotificationService notificationService,
            IReservationLockService reservationLockService)
        {
            _addonGetAll = addonGetAll;
            _accommodationService = accommodationService;
            _availabilityService = availabilityService;
            _env = env;
            _bookingAdd = bookingAdd;
            _userAdd = userAdd;
            _userGetByEmail = userGetByEmail;
            _userGetById = userGetById;
            _accommodationGetAll = accommodationGetAll;
            _accommodationConverter = accommodationConverter;
            _addressService = addressService;
            _priceCalculator = calculateTotalPrice;
            _parseDate = parseDate;
            _getSeasonForDate = getSeasonForDate;
            _notificationService = notificationService;
            _reservationLockService = reservationLockService;
        }

        [BindProperty(SupportsGet = true)]
        public int? UnitId { get; set; }

        [BindProperty(SupportsGet = true)]
        public string? PlaceKey { get; set; }

        [BindProperty(SupportsGet = true)]
        public int? AccommodationId { get; set; }

        [BindProperty(SupportsGet = true)]
        public string? Start { get; set; }

        [BindProperty(SupportsGet = true)]
        public string? End { get; set; }
        [BindProperty(SupportsGet = true)]
        public string? Category { get; set; }

        [BindProperty]
        public int BookingResidents { get; set; } = 1;

        [BindProperty]
        public int? CurrentUserId { get; set; }

        [BindProperty]
        public List<int> SelectedAddonIds { get; set; } = new();

        [BindProperty]
        [Required(ErrorMessage = "Navn skal udfyldes")]
        public string NewUserName { get; set; } = string.Empty;

        [BindProperty]
        [Required(ErrorMessage = "Email skal udfyldes")]
        [EmailAddress(ErrorMessage = "Indtast en gyldig email")]
        public string NewUserEmail { get; set; } = string.Empty;

        [BindProperty]
        [Required(ErrorMessage = "Adresse skal udfyldes")]
        public string NewUserAdress { get; set; } = string.Empty;
        [BindProperty]
        public bool AddressConfirmed { get; set; }

        public decimal AddonsTotal { get; set; }
        [BindProperty]
        public decimal? AdminDiscountPercent { get; set; }
        public decimal? PricePerNightWithSeason { get; private set; }
        public string? SeasonName { get; private set; }
        public List<decimal> NightlyBasePrices { get; private set; } = new();
        public List<decimal> NightlySeasonPrices { get; private set; } = new();
        public List<string> SeasonNames { get; private set; } = new();
        [BindProperty(SupportsGet = true)]
        public string? LockToken { get; set; }

        public bool LockValid { get; private set; } = false;

        // til view 
        public AccommodationDto? SelectedAccommodation { get; private set; }
        public List<AddonDto> Addons { get; private set; } = new();
        public string StartDisplay { get; private set; } = "—";
        public string EndDisplay { get; private set; } = "—";
        public int Days { get; private set; }
        public decimal? TotalPrice { get; private set; }
        public string TotalPriceDisplay { get; private set; } = "—";

        public async Task OnGetAsync()
        {
            // Datoer
            DateTime? startDt = _parseDate.ParseDate(Start, out var startDisp);
            DateTime? endDt = _parseDate.ParseDate(End, out var endDisp);
            StartDisplay = startDisp;
            EndDisplay = endDisp;

            await LoadPageDataAsync(startDt, endDt);

            // Hvis vi ikke fik id via querystring, brug cookie som fallback
            if (!AccommodationId.HasValue)
            {
                var cookieVal = Request.Cookies["selectedItem"];
                if (int.TryParse(cookieVal, out var idFromCookie))
                {
                    AccommodationId = idFromCookie;
                }
            }

            // Hvis user er logget ind skal input felter fyles ud
            if (User.Identity?.IsAuthenticated == true)
            {
                var (userId, adminId, role) = GetLoggedInUser();

                if (role == "User" && userId.HasValue)
                {
                    await UserInputFiller(userId.Value); // fill form til normal user
                }
            }
        }

        public async Task<IActionResult> OnPostAsync(string? applyDiscount)
        {
            // Parse dato
            DateTime? checkIn = _parseDate.ParseDate(Start, out var startDisp);
            DateTime? checkOut = _parseDate.ParseDate(End, out var endDisp);
            StartDisplay = startDisp;
            EndDisplay = endDisp;

            await LoadPageDataAsync(checkIn, checkOut);

            var result = await _priceCalculator.CalculateAsync(AccommodationId!.Value, SelectedAddonIds, checkIn, checkOut, BookingResidents);

            SelectedAccommodation = result.SelectedAccommodation;
            TotalPrice = result.TotalPrice;
            TotalPriceDisplay = result.TotalPriceDisplay;

            // Håndter rabat sepperat
            if (!string.IsNullOrEmpty(applyDiscount))
            {
                if (applyDiscount != "manual" && decimal.TryParse(applyDiscount, out var presetDiscount))
                {
                    AdminDiscountPercent = presetDiscount;
                }

                if (AdminDiscountPercent.HasValue && AdminDiscountPercent > 0)
                {
                    var discountFactor = 1 - (AdminDiscountPercent.Value / 100m);
                    TotalPrice = TotalPrice * discountFactor;
                    TotalPriceDisplay = TotalPrice?.ToString("F2");
                }

                return Page(); 
            }

            // Accommodation
            var list = await _accommodationGetAll.GetAllAccommodationsAsync();
            var listDto = await _accommodationConverter.AccommodationDtoConverter(list);
            if (AccommodationId.HasValue)
            {
                SelectedAccommodation = listDto.FirstOrDefault(a => a.AccommodationId == AccommodationId.Value);
            }

            // Tjekker om vi har det dato info vi skal bruge
            if (!checkIn.HasValue || !checkOut.HasValue || checkIn >= checkOut)
            {
                ModelState.AddModelError("", "Der skete en fejl med datoerne.");
                return Page();
            }

            if (SelectedAccommodation == null || !AccommodationId.HasValue)
            {
                ModelState.AddModelError("", "Der skete en fejl med den valgte enhed.");
                return Page();
            }

            int userId;

            if (!AddressConfirmed)
            {
                ModelState.AddModelError("", "Vælg en adresse fra listen.");
                return Page();
            }

            if (User.Identity?.IsAuthenticated == true)
            {
                var (loggedUserId, adminId, role) = GetLoggedInUser();

                if (role == "User" && loggedUserId.HasValue)
                {
                    userId = loggedUserId.Value;
                }
                else if (role == "Admin")
                {
                    if (!ModelState.IsValid)
                        return Page();

                    userId = await NewUserHandler(NewUserEmail, NewUserAdress, NewUserName);
                }
                else
                {
                    ModelState.AddModelError("", "Du har ikke tilladelse til at oprette en booking.");

                    return Page();
                }
            }
            else
            {
                if (!ModelState.IsValid)
                {
                    return Page();
                }

                var userExists = await _userGetByEmail.GetUserByEmailAsync(NewUserEmail);
                if (userExists == null)
                {
                    userId = await NewUserHandler(NewUserEmail, NewUserAdress, NewUserName);
                }
                else
                {
                    ModelState.AddModelError("", "En bruger med denne mail adresse findes allerede.");
                    return Page();
                }
            }

            var finalPrice = TotalPrice ?? 0m;
            if (AdminDiscountPercent.HasValue && AdminDiscountPercent > 0)
            {
                var discountFactor = 1 - (AdminDiscountPercent.Value / 100m);
                finalPrice = finalPrice * discountFactor;
            }
            var bookingDto = new BookingDto()
            {
                BookingResidents = BookingResidents,
                BookingPrice = (double)finalPrice,
                CheckInDate = checkIn.Value,
                CheckOutDate = checkOut.Value,
                UserId = userId,
                AccommodationId = AccommodationId.Value
            };

            try
            {
                // 1) Opret booking i DB
                await _bookingAdd.AddBookingAsync(bookingDto);

                // 2) Byg notification-objekt
                var noti = new BookingNotification
                {
                    UserEmail = NewUserEmail,
                    UserName = NewUserName,
                    Residents = BookingResidents,
                    Price = (double)finalPrice,
                    CheckInDate = checkIn.Value,
                    CheckOutDate = checkOut.Value,
                    AccommodationName = SelectedAccommodation.AccommodationName,
                    BookingResidents = BookingResidents
                };

                // 3) Send via service (der bruger HttpClient)
                await _notificationService.SendNotificationsAsync(noti);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[Confirmation] Fejl ved booking/notification:");
                Console.WriteLine(ex);
                ModelState.AddModelError("", $"Der skete en fejl: {ex.Message}");
                return Page();
            }

            return RedirectToPage("/ThankYou");
        }

        public async Task UserInputFiller(int userId)
        {
            UserDto user = await _userGetById.GetUserByIdAsync(userId);
            NewUserName = user.UserName;
            NewUserEmail = user.UserEmail;
            NewUserAdress = user.UserAdress;
        }

        public (int? UserId, int? AdminId, string? Role) GetLoggedInUser()
        {
            if (User?.Identity?.IsAuthenticated != true)
                return (null, null, null);

            var idClaim = User.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.NameIdentifier);
            var roleClaim = User.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Role);

            if (idClaim == null)
                return (null, null, null);

            if (roleClaim?.Value == "Admin" && int.TryParse(idClaim.Value, out var adminId))
                return (null, adminId, "Admin");

            if ((roleClaim == null || roleClaim.Value != "Admin") && int.TryParse(idClaim.Value, out var userId))
                return (userId, null, "User");

            return (null, null, null);
        }

        public async Task<int> NewUserHandler(string userEmail, string userAdress, string userName)
        {
            var newUser = new UserDto()
            {
                UserName = NewUserName,
                UserEmail = NewUserEmail,
                UserAdress = NewUserAdress,
            };

            // Sender den nye bruger til oprettelse
            await _userAdd.AddUserAsync(newUser);
            var createdUser = await _userGetByEmail.GetUserByEmailAsync(NewUserEmail);
            return createdUser.UserId;
        }

        private async Task LoadPageDataAsync(DateTime? startDt, DateTime? endDt)
        {
            var filePath = Path.Combine(_env.WebRootPath ?? string.Empty, "data", "contactinfo.txt");
            ContactInformation = ContactInfoReader.Load(filePath);

            Addons = (await _addonGetAll.GetAllAddonsAsync()).ToList();

            if (startDt.HasValue && endDt.HasValue)
                Days = Math.Max(0, (endDt.Value.Date - startDt.Value.Date).Days);

            var list = await _accommodationService.GetAccommodationsAsync(startDt, endDt);
            if (AccommodationId.HasValue)
                SelectedAccommodation = list.FirstOrDefault(a => a.AccommodationId == AccommodationId.Value);

            if (!string.IsNullOrWhiteSpace(Category))
                SelectedAccommodation = list.FirstOrDefault(a => string.Equals(a.Category, Category, StringComparison.OrdinalIgnoreCase));
            else
                SelectedAccommodation ??= list.FirstOrDefault();

            if (startDt.HasValue && endDt.HasValue && SelectedAccommodation != null)
            {
                NightlyBasePrices = new List<decimal>();
                NightlySeasonPrices = new List<decimal>();
                SeasonNames = new List<string>();

                for (var date = startDt.Value.Date; date < endDt.Value.Date; date = date.AddDays(1))
                {
                    var season = await _getSeasonForDate.GetSeasonForDate(date);
                    decimal basePrice = SelectedAccommodation.PricePerNight ?? 0m;
                    decimal seasonalPrice = basePrice * (season?.SeasonMultiplier ?? 1);

                    NightlyBasePrices.Add(basePrice);
                    NightlySeasonPrices.Add(seasonalPrice);
                    SeasonNames.Add(season?.SeasonName ?? "Normal Sæson");
                }

                PricePerNightWithSeason = NightlySeasonPrices.FirstOrDefault();
                SeasonName = SeasonNames.FirstOrDefault() ?? "Normal Sæson";
            }

            if (AccommodationId.HasValue)
            {
                var result = await _priceCalculator.CalculateAsync(AccommodationId.Value, SelectedAddonIds, startDt, endDt, BookingResidents);
                TotalPrice = result.TotalPrice;
                TotalPriceDisplay = result.TotalPriceDisplay;
            }
            if (string.IsNullOrEmpty(LockToken) || !AccommodationId.HasValue)
            {
                ModelState.AddModelError("", "Manglende reservationstoken. Start venligst din booking forfra");
            }

            var placeKeyPost = PlaceKey ?? string.Empty;
            var lockKey = $"{AccommodationId.Value}|{Start}|{End}|{placeKeyPost}";
            var valid = await _reservationLockService.ValidateTokenAsync(lockKey, LockToken);
            if (!valid)
            {
                ModelState.AddModelError("", "Reservationstoken er udløbet eller ugyldig. Booking blev ikke oprettet. Start venligts din booking forfra");
            }
        }
        public async Task<JsonResult> OnGetAddressSuggestionsAsync(string query)
        {
            if (string.IsNullOrWhiteSpace(query))
            {
                return new JsonResult(new List<string>());
            }
            var addresses = await _addressService.GetAddressesAsync(query);
            return new JsonResult(addresses);
        }
    }
}
