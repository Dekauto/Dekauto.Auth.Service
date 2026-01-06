using Dekauto.Auth.Service.Domain.Entities.DTO;
using Dekauto.Auth.Service.Domain.Entities.Models;

namespace Dekauto.Auth.Service.Domain.Interfaces
{
    public interface IUserAuthServiceDb
    {
        // Основной метод входа
        Task<TokensModel> AuthenticateAndGetTokensAsync(string login, string password);

        // Вспомогательные методы пользователя
        Task<UserDto?> GetUserByIdAsync(Guid userId); // НОВЫЙ МЕТОД ДЛЯ КОНТРОЛЛЕРА
        Task AddUserAsync(UserDto userDto, string password);
        Task UpdateUserAsync(Guid userId, UserDto updatedUserDto, string newPassword = null);
        Task ChangePasswordAsync(Guid userId, string newPassword, string? currentPassword, bool forceUpdate = false);

        // Хеширование
        string HashPassword(string password);
        bool VerifyHashedPassword(string hashedPassword, string providedPassword);

        // Работа с куки
        void SetRefreshTokenCookie(HttpResponse response, string refreshToken);
    }
}
