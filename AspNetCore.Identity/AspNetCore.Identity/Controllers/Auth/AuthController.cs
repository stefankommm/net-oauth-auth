using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AspNetCore.Identity.Database;
using AspNetCore.Identity.Services.Auth;
using Google.Apis.Util;

namespace AspNetCore.Identity.Controllers.Auth;


[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("google")]
    public async Task<IActionResult> GoogleLogin([FromBody] GoogleAuthRequest request)
    {
        try
        {
            string? jwt = await _authService.AuthenticateWithGoogleAsync(request.Token);
            if (jwt == null)
            {
                return BadRequest("Authentication failed.");
            }

            return Ok(new { token = jwt });
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(ex.Message);
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }
}


public class GoogleAuthRequest
{
    public string Token { get; set; }
}
