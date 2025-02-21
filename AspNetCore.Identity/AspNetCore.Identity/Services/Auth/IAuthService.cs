namespace AspNetCore.Identity.Services.Auth;

public interface IAuthService
{
    Task<string?> AuthenticateWithGoogleAsync(string googleToken);
}
