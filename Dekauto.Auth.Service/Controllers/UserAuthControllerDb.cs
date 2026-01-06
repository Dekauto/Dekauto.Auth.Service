using Dekauto.Auth.Service.Domain.Entities.Adapters;
using Dekauto.Auth.Service.Domain.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Dekauto.Auth.Service.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class UserAuthControllerDb : ControllerBase
    {
        private readonly IJwtTokenServiceDb jwtTokenService; // Сервис работы с токенами (БД)
        private readonly IUserAuthServiceDb userAuthService;   // Сервис работы с пользователями
        private readonly ILogger<UserAuthController> logger;

        public UserAuthControllerDb(
            IJwtTokenServiceDb jwtTokenService,
            IUserAuthServiceDb userAuthService,
            ILogger<UserAuthController> logger)
        {
            this.jwtTokenService = jwtTokenService;
            this.userAuthService = userAuthService;
            this.logger = logger;
        }

        [HttpPost]
        public async Task<ActionResult> AuthenticateAndGetTokensAsync([FromBody] LoginAdapter loginUser)
        {
            try
            {
                if (loginUser is null) throw new ArgumentNullException(nameof(loginUser));

                // Аутентификация и генерация токенов (с записью в БД)
                var tokensModel = await userAuthService.AuthenticateAndGetTokensAsync(loginUser.Login, loginUser.Password);

                if (tokensModel is null) return StatusCode(StatusCodes.Status401Unauthorized, "Неверный логин или пароль.");

                // Устанавливаем RefreshToken в HttpOnly cookie через сервис (чтобы использовать общие настройки)
                userAuthService.SetRefreshTokenCookie(Response, tokensModel.RefreshToken.Token);

                logger.LogInformation($"User {loginUser.Login} authenticated.");
                return Ok(tokensModel.TokenAdapter);
            }
            catch (KeyNotFoundException ex)
            {
                logger.LogWarning(ex, $"User {loginUser.Login} not found during auth.");
                return StatusCode(StatusCodes.Status404NotFound, "Пользователь не найден.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Auth error.");
                return StatusCode(StatusCodes.Status500InternalServerError, "Ошибка сервера при входе.");
            }
        }

        [HttpPost("{userId}/refresh")]
        public async Task<ActionResult> RefreshTokensAsync(Guid userId)
        {
            try
            {
                // 1. Получаем токен из куки
                var refreshTokenRaw = Request.Cookies["refreshToken"];
                if (string.IsNullOrEmpty(refreshTokenRaw))
                {
                    return StatusCode(StatusCodes.Status403Forbidden, "Refresh token is missing");
                }

                // 2. Получаем DTO пользователя для генерации новых токенов
                var userDto = await userAuthService.GetUserByIdAsync(userId);
                if (userDto == null)
                {
                    return StatusCode(StatusCodes.Status403Forbidden, "User context not found");
                }

                // 3. Вызываем сервис обновления токенов (Проверка в БД -> Ротация -> Генерация новых)
                var result = await jwtTokenService.TryRefreshTokensAsync(refreshTokenRaw, userDto);

                if (!result.Success || result.Tokens == null)
                {
                    // Если токен невалиден/отозван/просрочен — очищаем куку
                    Response.Cookies.Delete("refreshToken");
                    return StatusCode(StatusCodes.Status403Forbidden, "Invalid refresh token");
                }

                // 4. Устанавливаем новый RefreshToken в куки
                userAuthService.SetRefreshTokenCookie(Response, result.Tokens.RefreshToken.Token);

                return Ok(result.Tokens.TokenAdapter);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Refresh token error.");
                return StatusCode(StatusCodes.Status500InternalServerError, "Ошибка сервера при обновлении токена.");
            }
        }

        [HttpGet("validate")]
        [Authorize]
        public IActionResult ValidateAccessToken()
        {
            // Middleware (TokenRevocationMiddleware) уже проверил, не заблокирован ли JTI в базе.
            // Если код дошел сюда, значит токен валиден и активен.
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var login = User.FindFirst(ClaimTypes.Name)?.Value;
            var role = User.FindFirst(ClaimTypes.Role)?.Value;

            return Ok(new { UserId = userId, Login = login, Role = role, Status = "Active" });
        }
    }
}