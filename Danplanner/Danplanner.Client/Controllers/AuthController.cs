using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Danplanner.Application.Models.LoginDto;
using Danplanner.Application.Models.ModelsDto;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Danplanner.Application.Interfaces.AdminInterfaces;
using Danplanner.Application.Interfaces.AuthInterfaces.IUserRegister;
using Danplanner.Application.Interfaces.AuthInterfaces.IUserLogin;
using Danplanner.Application.Interfaces.AuthInterfaces;
using Danplanner.Application.Interfaces.BruteForceDetectionInterfaces;
using Danplanner.Application.Interfaces.UserInterfaces;
using Danplanner.Application.Interfaces.LogInterfaces;
using Danplanner.Application.Models;
using Microsoft.AspNetCore.RateLimiting;

namespace Danplanner.Client.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAdminGetById _adminGetById;
        private readonly IAdminRegister _adminRegisterService;
        private readonly ILogin _loginService;
        private readonly IUserRegister _userRegisterService;
        private readonly IUserRequestLoginCode _userRequestLoginCode;
        private readonly IUserVerifyLoginCode _userVerifyLoginCode;
        private readonly IUserRequestRegisterCode _userRequestRegisterCode;
        private readonly IUserVerifyRegisterCode _userVerifyRegisterCode;
        private readonly IBruteForceDetection _bruteForce;
        private readonly IUserGetByEmail _userGetByEmail;
        private readonly IUserUpdate _userUpdate;
        private readonly ISecurityLogger _securityLogger;

        public AuthController(
            IAdminGetById adminIdService,
            IAdminRegister adminRegisterService,
            ILogin loginService,
            IUserRegister userRegisterService,
            IUserRequestLoginCode userRequestLoginCode,
            IUserVerifyLoginCode userVerifyLoginCode,
            IUserRequestRegisterCode userRequestRegisterCode,
            IUserVerifyRegisterCode userVerifyRegisterCode,
            IBruteForceDetection bruteForce,
            IUserGetByEmail userGetByEmail,
            IUserUpdate userUpdate,
            ISecurityLogger securityLogger
            )
        {
            _adminGetById = adminIdService;
            _adminRegisterService = adminRegisterService;
            _loginService = loginService;
            _userRegisterService = userRegisterService;
            _userRequestLoginCode = userRequestLoginCode;
            _userVerifyLoginCode = userVerifyLoginCode;
            _userRequestRegisterCode = userRequestRegisterCode;
            _userVerifyRegisterCode = userVerifyRegisterCode;
            _bruteForce = bruteForce;
            _userGetByEmail = userGetByEmail;
            _userUpdate = userUpdate;
            _securityLogger = securityLogger;
        }

        [HttpPost("register")]
        public async Task<ActionResult<AdminDto>> RegisterAdmin([FromBody] AdminDto request)
        {
            var admin = await _adminRegisterService.RegisterAdminAsync(request);
            if (admin == null)
                return BadRequest("Admin already exists.");
            return Ok(admin);
        }

        [HttpPost("admin/check-id")]
        public async Task<IActionResult> CheckAdminId([FromBody] AdminIdDto request)
        {
            var admin = await _adminGetById.GetAdminByIdAsync(request.AdminId);

            if (admin == null)
                return NotFound("Admin ID does not exist.");

            return Ok();
        }

        public class AdminIdDto
        {
            public int AdminId { get; set; }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto request)
        {
            if (!string.IsNullOrEmpty(request.Email))
            {
                var user = await _userGetByEmail.GetUserByEmailAsync(request.Email);
                if (user != null && user.IsLocked)
                    return StatusCode(403, "Din konto er låst. Kontakt venligst support.");
            }

            var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
            var token = await _loginService.LoginAsync(request);

            if (token == null)
            {
                await _securityLogger.LogAsync(SecurityLogTypes.FailedLogin, "Fejlet admin login forsøg", request.Email, ip);
                return BadRequest("Invalid credentials or code.");
            }

            if (token == "OTP_SENT")
            {
                await _securityLogger.LogAsync(SecurityLogTypes.OtpRequested, "OTP sendt til bruger", request.Email, ip);
                return Ok("OTP sent to your email.");
            }

            await _securityLogger.LogAsync(SecurityLogTypes.SuccessLogin, "Vellykket login", request.Email, ip);

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);
            var claims = jwt.Claims.ToList();
            var identity = new ClaimsIdentity(claims, "jwt");
            var userPrincipal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync("Cookies", userPrincipal);

            return Ok(token);
        }

        [HttpPost("user/request-code")]
        public async Task<IActionResult> RequestUserCode([FromBody] RequestCodeDto request)
        {
            var user = await _userGetByEmail.GetUserByEmailAsync(request.UserEmail);
            if (user == null)
                return NotFound("Bruger ikke fundet.");
            if (user.IsLocked)
                return StatusCode(403, "Din konto er låst. Kontakt venligst support.");

            await _userRequestLoginCode.RequestUserLoginCodeAsync(request.UserEmail);
            return Ok("Login kode sendt til din email.");
        }

        [EnableRateLimiting("fixed")]
        [HttpPost("user/verify-code")]
        public async Task<ActionResult<string>> VerifyUserCode([FromBody] VerifyCodeDto request)
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

            if (_bruteForce.IsLockedOut(request.UserEmail))
            {
                await _securityLogger.LogAsync(SecurityLogTypes.RateLimitHit, "Bruger ramt rate limit", request.UserEmail, ip);
                return StatusCode(429, "Too many failed attempts. Try again later.");
            }

            var token = await _userVerifyLoginCode.VerifyUserLoginCodeAsync(request.UserEmail, request.Code);
            if (token == null)
            {
                _bruteForce.RecordFailedAttempt(request.UserEmail);
                await _securityLogger.LogAsync(SecurityLogTypes.FailedLogin, "Forkert OTP kode", request.UserEmail, ip);

                if (_bruteForce.IsLockedOut(request.UserEmail))
                {
                    var user = await _userGetByEmail.GetUserByEmailAsync(request.UserEmail);
                    if (user != null)
                    {
                        await _userUpdate.LockUser(user);
                        await _securityLogger.LogAsync(SecurityLogTypes.AccountLocked, "Konto låst efter for mange fejlede forsøg", request.UserEmail, ip);
                    }
                }

                return BadRequest("Invalid code.");
            }

            _bruteForce.RecordSuccessfulLogin(request.UserEmail);
            await _securityLogger.LogAsync(SecurityLogTypes.SuccessLogin, "Vellykket bruger login via OTP", request.UserEmail, ip);

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);
            var claims = jwt.Claims.ToList();
            var identity = new ClaimsIdentity(claims, "jwt");
            var userPrincipal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync("Cookies", userPrincipal);

            return Ok(token);
        }

        [HttpPost("user/request-register-code")]
        public async Task<IActionResult> RequestUserRegisterCode([FromBody] RequestCodeDto request)
        {
            var success = await _userRequestRegisterCode.RequestUserRegisterCodeAsync(request.UserEmail);
            if (!success)
                return BadRequest("Kunne ikke sende OTP.");
            return Ok("OTP sendt til din email.");
        }

        [HttpPost("user/verify-register-code")]
        public async Task<IActionResult> VerifyUserRegisterCode([FromBody] VerifyCodeDto request)
        {
            var isValid = _userVerifyRegisterCode.VerifyUserRegisterCode(request.UserEmail, request.Code);
            if (!isValid)
                return BadRequest("Forkert eller udløbet OTP.");

            return Ok("OTP verificeret!");
        }

        [HttpPost("user/register-user")]
        public async Task<IActionResult> RegisterUser([FromBody] UserDto request)
        {
            var user = await _userRegisterService.RegisterUserAsync(request);
            if (user == null)
                return BadRequest("Email er allerede i brug.");
            return Ok(user);
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToPage("/Index");
        }

        [Authorize]
        [HttpGet("authenticated-only")]
        public IActionResult AuthenticatedOnly()
        {
            return Ok($"You are authenticated as {User.Identity?.Name ?? "Unknown"}!");
        }
    }
}
