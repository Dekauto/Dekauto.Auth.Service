using Dekauto.Auth.Service.Domain.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dekauto.Auth.Service.Controllers
{
    [Route("api")]
    [ApiController]
    [Authorize(Policy = "OnlyAdmin")] // ТОЛЬКО ДЛЯ АДМИНОВ
    public class UserManagementController : ControllerBase
    {
        private readonly IUserManagementService userManagementService;
        private readonly ILogger<UserManagementController> logger;

        public UserManagementController(IUserManagementService userManagementService, ILogger<UserManagementController> logger)
        {
            this.userManagementService = userManagementService;
            this.logger = logger;
        }

        // GET /api/users/{userId}/sessions
        [HttpGet("users/{userId}/sessions")]
        public async Task<IActionResult> GetUserSessions(Guid userId)
        {
            try
            {
                var sessions = await userManagementService.GetUserSessionsAsync(userId);
                return Ok(sessions);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Error getting sessions for user {userId}");
                return StatusCode(500, "Ошибка при получении списка сессий.");
            }
        }

        // POST /api/users/{userId}/revoke-all
        [HttpPost("users/{userId}/revoke-all")]
        public async Task<IActionResult> RevokeAllSessions(Guid userId)
        {
            try
            {
                // Получаем имя админа, который делает запрос, для логов/причины
                var adminLogin = User.Identity?.Name ?? "Admin";
                var reason = $"Revoked by administrator {adminLogin}";

                await userManagementService.RevokeAllUserSessionsAsync(userId, reason);

                logger.LogInformation($"All sessions for user {userId} were revoked by {adminLogin}.");
                return Ok(new { Message = "Все сессии пользователя успешно отозваны." });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Error revoking all sessions for user {userId}");
                return StatusCode(500, "Ошибка при отзыве сессий.");
            }
        }

        // POST /api/sessions/{jti}/revoke
        [HttpPost("sessions/{jti}/revoke")]
        public async Task<IActionResult> RevokeSession(string jti)
        {
            try
            {
                var adminLogin = User.Identity?.Name ?? "Admin";
                var reason = $"Session revoked manually by administrator {adminLogin}";

                await userManagementService.RevokeSessionAsync(jti, reason);

                logger.LogInformation($"Session {jti} was revoked by {adminLogin}.");
                return Ok(new { Message = "Сессия успешно отозвана." });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Error revoking session {jti}");
                return StatusCode(500, "Ошибка при отзыве сессии.");
            }
        }
    }
}
