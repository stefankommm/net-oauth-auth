using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AspNetCore.Identity.Database;
using Google.Apis.Util;

namespace AspNetCore.Identity.Controllers.Auth;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly IConfiguration _configuration;

    public AuthController(UserManager<User> userManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _configuration = configuration;
    }

    [HttpPost("google")]
    public async Task<IActionResult> GoogleLogin([FromBody] GoogleAuthRequest request)
    {
        if (string.IsNullOrEmpty(request.Token))
        {
            return BadRequest("Google token is required.");
        }

        try
        {
            // ✅ Verify Google Token
            var settings = new GoogleJsonWebSignature.ValidationSettings {
                Audience = new[] { _configuration["Google:ClientId"] }
            };
            
            
            GoogleJsonWebSignature.Payload payload = await GoogleJsonWebSignature.ValidateAsync(request.Token, settings);

            // ✅ Check if user exists in ASP.NET Identity
            User? user = await _userManager.FindByEmailAsync(payload.Email);
            user.ThrowIfNull("User not found");
            
            
            if (user == null)
            {
                // ✅ Create new Identity user
                user = new User
                {
                    UserName = payload.Email,
                    Email = payload.Email,
                };

                var result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    return BadRequest("Failed to create user.");
                }
            }

            // ✅ Generate JWT Token for the user
            var tokenHandler = new JwtSecurityTokenHandler();
            byte[] key = Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"] ?? "super_secret_key_12345678901234567890");

            if (user.Email == null)
            {
                throw new Exception("bruh");
            }
            Claim[] claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),

            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(24),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            string jwt = tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));

            return Ok(new { token = jwt });
        }
        catch (Exception ex)
        {
            return Unauthorized($"Invalid Google token: {ex.Message}");
        }
    }
}

public class GoogleAuthRequest
{
    public string Token { get; set; }
}
