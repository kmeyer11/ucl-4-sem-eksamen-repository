using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Danplanner.Application.Interfaces.AuthInterfaces.ITokenService;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Domain.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Danplanner.Application.Services
{
    public class TokenService : IAdminCreateToken, IUserCreateToken
    {
        private readonly IConfiguration _configuration;

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string CreateTokenForAdmin(Admin admin)
        {
            var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, admin.AdminId.ToString()),
            new Claim(ClaimTypes.NameIdentifier, admin.AdminId.ToString()),
            new Claim(ClaimTypes.Role, "Admin")
        };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration.GetValue<string>("AppSettings:Token")!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken(
                issuer: _configuration.GetValue<string>("AppSettings:Issuer"),
                audience: _configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }

        public string CreateTokenForUser(UserDto user)
        {
            var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName.ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString())
        };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("AppSettings:Token")!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var token = new JwtSecurityToken(
                issuer: _configuration.GetValue<string>("AppSettings:Issuer"),
                audience: _configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}
