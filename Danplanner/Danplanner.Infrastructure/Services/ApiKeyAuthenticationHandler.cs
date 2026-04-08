using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Danplanner.Domain.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Danplanner.Infrastructure.Services
{
    public class ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {        
        public static readonly string SchemeName = "ApiKey";

        public ApiKeyAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder urlEncoder
            ) : base(options, loggerFactory, urlEncoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("api-key", out var apiKeyHeader))
            {
                return Task.FromResult(AuthenticateResult.Fail("Api key is missing"));
            }
            if (apiKeyHeader != "hemmelig-nøgle")
            {
                return Task.FromResult(AuthenticateResult.Fail("Invalid API key"));
            }

            var identity = new ClaimsIdentity(
                [new Claim(ClaimTypes.Name, SchemeName)], SchemeName
            );

            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = 401;
            return Task.CompletedTask;
        }
    }
}