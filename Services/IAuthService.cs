using AuthJwtAPI.Entities;
using AuthJwtAPI.Model;

namespace AuthJwtAPI.Services
{
    public interface IAuthService
    {
        Task<TokenResponseDto?> LoginAsync(UserDto request);
        Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenResponseDto request);
        Task<User?> RegisterAsync(UserDto request);
    }
}