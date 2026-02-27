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

        public AuthController( 
            IAdminGetById adminIdService, 
            IAdminRegister adminRegisterService, 
            ILogin loginService, 
            IUserRegister userRegisterService, 
            IUserRequestLoginCode userRequestLoginCode, 
            IUserVerifyLoginCode userVerifyLoginCode,
            IUserRequestRegisterCode userRequestRegisterCode,
            IUserVerifyRegisterCode userVerifyRegisterCode
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
            var token = await _loginService.LoginAsync(request);

            if (token == null)
                return BadRequest("Invalid credentials or code.");

            if (token == "OTP_SENT")
                return Ok("OTP sent to your email.");

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
            var success = await _userRequestLoginCode.RequestUserLoginCodeAsync(request.UserEmail);
            if (!success)
                return NotFound("User not found.");
            return Ok("Login code sent to your email.");
        }

        [HttpPost("user/verify-code")]
        public async Task<ActionResult<string>> VerifyUserCode([FromBody] VerifyCodeDto request)
        {
            var token = await _userVerifyLoginCode.VerifyUserLoginCodeAsync(request.UserEmail, request.Code);
            if (token == null)
                return BadRequest("Invalid code.");

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
