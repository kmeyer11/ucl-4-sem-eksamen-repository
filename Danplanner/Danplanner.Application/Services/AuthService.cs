using System.Collections.Concurrent;
using Danplanner.Application.Interfaces.AdminInterfaces;
using Danplanner.Application.Interfaces.AuthInterfaces;
using Danplanner.Application.Interfaces.AuthInterfaces.ITokenService;
using Danplanner.Application.Interfaces.AuthInterfaces.IUserLogin;
using Danplanner.Application.Interfaces.AuthInterfaces.IUserRegister;
using Danplanner.Application.Interfaces.UserInterfaces;
using Danplanner.Application.Models.LoginDto;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace Danplanner.Application.Services
{
    public class AuthService : IAdminRegister, IUserRegister, ILogin, IUserRequestLoginCode, IUserVerifyLoginCode, IUserRequestRegisterCode, IUserVerifyRegisterCode
    {
        private readonly IAdminGetById _adminGetById;
        private readonly IAdminAdd _adminAdd;
        private readonly IUserCreateToken _userToken;
        private readonly IAdminCreateToken _adminToken;
        private readonly PasswordHasher<Admin> _passwordHasher;
        private readonly IUserGetByEmail _userRepository;
        private readonly IEmailService _emailService;
        private readonly IUserAdd _addUserByEmail;

        private static readonly ConcurrentDictionary<string, UserOtp> _userOtps = new();

        public AuthService(
            IAdminGetById adminGetById,
            IAdminAdd adminAdd,
            IUserGetByEmail userRepository,
            IEmailService emailService,
            IUserAdd addUserByEmail,
            IUserCreateToken userToken,
            IAdminCreateToken adminToken)
        {
            _adminGetById = adminGetById;
            _adminAdd = adminAdd;
            _userRepository = userRepository;
            _userToken = userToken;
            _adminToken = adminToken;
            _emailService = emailService;
            _passwordHasher = new PasswordHasher<Admin>();
            _addUserByEmail = addUserByEmail;
        }

        // Token Creation
        private string CreateTokenForAdmin(Admin admin) => _adminToken.CreateTokenForAdmin(admin);
        private string CreateTokenForUser(UserDto user) => _userToken.CreateTokenForUser(user);

        // Admin Registration
        public async Task<AdminDto> RegisterAdminAsync(AdminDto request)
        {
            var existingAdmin = await _adminGetById.GetAdminByIdAsync(request.AdminId);
            if (existingAdmin != null)
                return null;

            var admin = new Admin
            {
                AdminId = request.AdminId,
                AdminPassword = _passwordHasher.HashPassword(null, request.AdminDtoPassword)
            };

            await _adminAdd.AddAdminAsync(admin);

            return new AdminDto
            {
                AdminId = admin.AdminId,
                AdminDtoPassword = null
            };
        }

        // User Registration
        public async Task<UserDto> RegisterUserAsync(UserDto request)
        {
            var existingUser = await _userRepository.GetUserByEmailAsync(request.UserEmail);
            if (existingUser != null)
                return null;

            var user = new UserDto
            {
                UserAdress = request.UserAdress,
                UserMobile = request.UserMobile,
                UserEmail = request.UserEmail,
                UserName = request.UserName,
            };

            await _addUserByEmail.AddUserAsync(user);

            return user;
        }


        // Login (Admin & User OTP)
        public async Task<string?> LoginAsync(LoginDto request)
        {
            // Admin login
            if (request.AdminId.HasValue && !string.IsNullOrEmpty(request.Password))
            {
                var admin = await _adminGetById.GetAdminByIdAsync(request.AdminId.Value);
                if (admin == null) return null;

                var result = _passwordHasher.VerifyHashedPassword(admin, admin.AdminPassword, request.Password);
                if (result == PasswordVerificationResult.Success)
                    return CreateTokenForAdmin(admin);

                return null;
            }

            // User OTP login
            if (!string.IsNullOrEmpty(request.Email))
            {
                var user = await _userRepository.GetUserByEmailAsync(request.Email);
                if (user == null) return null;

                if (string.IsNullOrEmpty(request.Code))
                {
                    var code = new Random().Next(100000, 999999).ToString();
                    var otp = new UserOtp
                    {
                        Code = code,
                        Expiration = DateTime.UtcNow.AddMinutes(1)
                    };

                    _userOtps[request.Email] = otp;

                    // Send email
                    await _emailService.SendEmailAsync(
                        request.Email,
                        "Your OTP Code",
                        $"Your OTP code is <b>{code}</b>. It expires in 5 minutes."
                    );

                    return "OTP_SENT";
                }

                // Verificer OTP
                if (_userOtps.TryGetValue(request.Email, out var storedOtp))
                {
                    if (storedOtp.Expiration < DateTime.UtcNow)
                    {
                        _userOtps.TryRemove(request.Email, out _);
                        return null; // OTP expired
                    }

                    if (storedOtp.Code == request.Code)
                    {
                        _userOtps.TryRemove(request.Email, out _);
                        return CreateTokenForUser(user);
                    }
                }

                return null; // wrong OTP
            }

            return null; // no credentials provided
        }

        // Request OTP separately
        public async Task<bool> RequestUserLoginCodeAsync(string email)
        {
            var user = await _userRepository.GetUserByEmailAsync(email);
            if (user == null) return false;

            var code = new Random().Next(100000, 999999).ToString();
            var otp = new UserOtp
            {
                Code = code,
                Expiration = DateTime.UtcNow.AddMinutes(5)
            };

            _userOtps[email] = otp;

            // Send email
            await _emailService.SendEmailAsync(
                email,
                "Your OTP Code",
                $"Your login OTP code is <b>{code}</b>. It expires in 5 minutes."
            );

            return true;
        }
        public async Task<bool> RequestUserRegisterCodeAsync(string email)
        {
            // Vi sender OTP til registrering selvom email ikke findes endnu
            var code = new Random().Next(100000, 999999).ToString();
            _userOtps[email] = new UserOtp
            {
                Code = code,
                Expiration = DateTime.UtcNow.AddMinutes(5)
            };

            try
            {
                await _emailService.SendEmailAsync(
                    email,
                    "Din registrerings-OTP",
                    $"Din OTP kode er <b>{code}</b>. Den udløber om 5 minutter."
                );
                return true;
            }
            catch
            {
                return false;
            }
        }



        // Verify OTP separately
        public async Task<string?> VerifyUserLoginCodeAsync(string email, string code)
        {
            if (!_userOtps.TryGetValue(email, out var storedOtp))
                return null;

            if (storedOtp.Expiration < DateTime.UtcNow)
            {
                _userOtps.TryRemove(email, out _);
                return null; // expired
            }

            if (storedOtp.Code != code)
                return null; // wrong code

            _userOtps.TryRemove(email, out _);

            var user = await _userRepository.GetUserByEmailAsync(email);
            if (user == null) return null;

            return CreateTokenForUser(user);
        }

        public bool VerifyUserRegisterCode(string email, string code)
        {
            if (!_userOtps.TryGetValue(email, out var storedOtp))
                return false; // OTP findes ikke

            if (storedOtp.Expiration < DateTime.UtcNow)
            {
                _userOtps.TryRemove(email, out _);
                return false; // OTP udløbet
            }

            if (storedOtp.Code != code)
                return false; // Forkert kode

            _userOtps.TryRemove(email, out _);
            return true; // OTP korrekt
        }

        // Helper class for OTP
        private class UserOtp
        {
            public string Code { get; set; } = null!;
            public DateTime Expiration { get; set; }
        }
    }
}
