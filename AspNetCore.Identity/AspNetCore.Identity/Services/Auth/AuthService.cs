using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AspNetCore.Identity.Database;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCore.Identity.Services.Auth;

public class AuthService : IAuthService
{
    private readonly UserManager<User> _userManager;
    private readonly IConfiguration _configuration;

    public AuthService(UserManager<User> userManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _configuration = configuration;
    }

    public async Task<string?> AuthenticateWithGoogleAsync(string googleToken)
    {
        if (string.IsNullOrEmpty(googleToken))
        {
            throw new ArgumentException("Google token is required.");
        }

        try
        {
            var settings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new[] { _configuration["Google:ClientId"] }
            };

            GoogleJsonWebSignature.Payload payload = await GoogleJsonWebSignature.ValidateAsync(googleToken, settings);


            User? user = await _userManager.FindByEmailAsync(payload.Email);
            if (user == null)
            {
                user = new User
                {
                    UserName = payload.Email,
                    Email = payload.Email
                };

                IdentityResult result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    throw new Exception("Failed to create user.");
                }
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            byte[] key =
                Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"] ?? "super_secret_key_12345678901234567890");

            if (user.Email == null)
            {
                throw new Exception("User email is null.");
            }

            Claim[] claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email)
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(24),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            string jwt = tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));
            return jwt;
        }
        catch (Exception ex)
        {
            throw new UnauthorizedAccessException($"Invalid Google token: {ex.Message}");
        }
    }
}
