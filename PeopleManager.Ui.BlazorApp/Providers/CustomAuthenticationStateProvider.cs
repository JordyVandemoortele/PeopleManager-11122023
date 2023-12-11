using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Newtonsoft.Json.Linq;
using Vives.Authentication.Abstractions;
using Vives.Security.Jwt;

namespace PeopleManager.Ui.BlazorApp.Providers
{
    public class CustomAuthenticationStateProvider(ITokenStore tokenStore): AuthenticationStateProvider
    {
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            //Get bearer from TokenStore
            var token = await tokenStore.GetToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                return new AuthenticationState(new ClaimsPrincipal());
            }

            //Convert token to ClaimsPrincipal
            var claimsPrincipal = JwtSecurityHelper.GetClaimsPrincipal(token, "Bearer");

            return new AuthenticationState(claimsPrincipal);
        }
    }
}
