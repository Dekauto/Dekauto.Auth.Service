using Dekauto.Auth.Service.Domain.Entities;
using Dekauto.Auth.Service.Domain.Entities.DTO;
using Dekauto.Auth.Service.Domain.Entities.Models;
using Dekauto.Auth.Service.Domain.Interfaces;
using Microsoft.AspNetCore.Identity;
using System.Security.Authentication;
using System.Text.Json;

namespace Dekauto.Auth.Service.Services
{
    public class UserAuthServiceDb : IUserAuthServiceDb
    {
        private readonly IUsersRepository usersRepository;
        private readonly IRolesService rolesService;
        private readonly IJwtTokenServiceDb jwtTokenService;

        private readonly IConfiguration configuration;
        private readonly PasswordHasher<object> hasher;

        public UserAuthServiceDb(IUsersRepository usersRepository, IRolesService rolesService,
            IJwtTokenServiceDb jwtTokenService, IConfiguration configuration)
        {
            this.usersRepository = usersRepository;
            this.jwtTokenService = jwtTokenService;
            this.configuration = configuration;
            this.rolesService = rolesService;
            hasher = new PasswordHasher<object>();
        }

        public async Task<TokensModel> AuthenticateAndGetTokensAsync(string login, string password)
        {
            if (string.IsNullOrEmpty(login) || string.IsNullOrEmpty(password)) throw new ArgumentException();

            var userAccount = await usersRepository.GetByLoginAsync(login);
            if (userAccount == null) throw new KeyNotFoundException($"Пользователь {login} не найден");

            var result = hasher.VerifyHashedPassword(userAccount, userAccount.PasswordHash, password);

            if (result == PasswordVerificationResult.Success || result == PasswordVerificationResult.SuccessRehashNeeded)
            {
                var tokensModel = await jwtTokenService.GenerateTokensAsync(ToDto(userAccount));
                return tokensModel;
            }
            else
            {
                return null;
            }
        }

        // Нужен контроллеру для Refresh Flow
        public async Task<UserDto?> GetUserByIdAsync(Guid userId)
        {
            var user = await usersRepository.GetByIdAsync(userId);
            if (user == null) return null;
            return ToDto(user);
        }

        public void SetRefreshTokenCookie(HttpResponse response, string refreshToken)
        {
            if (response is null) throw new ArgumentNullException(nameof(response));
            if (string.IsNullOrEmpty(refreshToken)) throw new ArgumentException($"'{nameof(refreshToken)}' cannot be null or empty.", nameof(refreshToken));

            // Безопасное получение настройки HTTPS
            var useHttps = configuration.GetValue<bool>("UseHttps");

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(Convert.ToDouble(configuration["Jwt:RefreshTokenExpireDays"] ?? "7")),
                Secure = useHttps,
                SameSite = SameSiteMode.Strict,
                Path = "/api/auth" // Кука будет отправляться только на этот путь
            };

            var deleteOptions = new CookieOptions
            {
                Path = "/",
                Secure = useHttps,
                SameSite = SameSiteMode.None // Для гарантированного удаления
            };

            // Удаляем старую куку перед установкой новой
            response.Cookies.Delete("refreshToken", deleteOptions);
            response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }

        public bool VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            var result = hasher.VerifyHashedPassword(null, hashedPassword, providedPassword);
            return result == PasswordVerificationResult.Success || result == PasswordVerificationResult.SuccessRehashNeeded;
        }

        public string HashPassword(string password)
        {
            return hasher.HashPassword(null, password);
        }

        public async Task AddUserAsync(UserDto userDto, string password)
        {
            if (userDto is null) throw new ArgumentNullException(nameof(userDto));

            var passwordHash = HashPassword(password);
            var role = await rolesService.GetByRoleNameAsync(userDto.RoleName);
            if (role == null) throw new KeyNotFoundException($"Роль {userDto.EngRoleName} не найдена");

            var newUser = await FromDtoAsync(userDto);
            newUser.PasswordHash = passwordHash;
            newUser.RoleId = role.Id;

            await usersRepository.AddAsync(newUser);
        }

        public async Task UpdateUserAsync(Guid userId, UserDto updatedUserDto, string? newPassword = null)
        {
            if (updatedUserDto == null) throw new ArgumentNullException("Не все аргументы переданы.");
            if (updatedUserDto.Id != userId) throw new ArgumentException("ID не совпадают.");

            var user = await usersRepository.GetByIdAsync(userId);
            if (user == null)
                throw new InvalidOperationException($"Пользователь с Id = {userId} не найден.");

            user.Login = updatedUserDto.Login;

            if (!string.IsNullOrWhiteSpace(newPassword))
            {
                user.PasswordHash = HashPassword(newPassword);
            }

            if (!string.IsNullOrWhiteSpace(updatedUserDto.RoleName))
            {
                var role = await rolesService.GetByRoleNameAsync(updatedUserDto.RoleName);
                if (role == null)
                    throw new InvalidOperationException($"Роль '{updatedUserDto.EngRoleName}' не найдена.");
                user.RoleId = role.Id;
                user.Role = role;
            }
            await usersRepository.UpdateAsync(user);
        }

        public async Task ChangePasswordAsync(string login, string newPassword, string? currentPassword, bool forceUpdate = false)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(newPassword);
            var currentUser = await usersRepository.GetByLoginAsync(login);
            if (currentUser == null) throw new KeyNotFoundException();

            if (forceUpdate)
            {
                var isForceAllowed = configuration.GetValue<bool>("AllowForcePasswordChange", false);
                if (isForceAllowed)
                {
                    currentUser.PasswordHash = HashPassword(newPassword);
                    await usersRepository.UpdateAsync(currentUser);
                }
                else
                {
                    throw new InvalidOperationException("Принудительная смена пароля запрещена конфигурацией.");
                }
            }
            else
            {
                if (VerifyHashedPassword(currentUser.PasswordHash, currentPassword))
                {
                    currentUser.PasswordHash = HashPassword(newPassword);
                    await usersRepository.UpdateAsync(currentUser);
                }
                else
                {
                    throw new InvalidCredentialException("Неверный пароль.");
                }
            }
        }

        public DEST JsonSerializationConvert<SRC, DEST>(SRC src)
        {
            return JsonSerializer.Deserialize<DEST>(JsonSerializer.Serialize(src));
        }

        public async Task<User> FromDtoAsync(UserDto userDto)
        {
            if (userDto == null) throw new ArgumentNullException(nameof(userDto));

            var user = await usersRepository.GetByIdAsync(userDto.Id);
            user ??= JsonSerializationConvert<UserDto, User>(userDto);

            return user;
        }

        public UserDto ToDto(User user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            var userDto = JsonSerializationConvert<User, UserDto>(user);

            if (user.Role == null)
            {
                Console.WriteLine($"WARNING: роль == null у пользователя {user.Id}");
                userDto.RoleName = null;
                userDto.EngRoleName = null;
            }
            else
            {
                userDto.RoleName = user.Role.Name;
                userDto.EngRoleName = user.Role.EngName;
            }
            return userDto;
        }

        public IEnumerable<UserDto> ToDtos(IEnumerable<User> users)
        {
            if (users == null) throw new ArgumentNullException(nameof(users));
            var userDtos = new List<UserDto>();
            foreach (var user in users)
            {
                userDtos.Add(ToDto(user));
            }
            return userDtos;
        }
    }
}
