using Dekauto.Auth.Service.Domain.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace Dekauto.Auth.Service.Controllers
{
    [Route("api/internal")]
    [ApiController]
    public class InternalTokenController : ControllerBase
    {
        private readonly ITokenRepository tokenRepository;
        private readonly ILogger<InternalTokenController> logger;

        public InternalTokenController(ITokenRepository tokenRepository, ILogger<InternalTokenController> logger)
        {
            this.tokenRepository = tokenRepository;
            this.logger = logger;
        }

        // GET /api/internal/tokens/{jti}/status
        [HttpGet("tokens/{jti}/status")]
        public async Task<IActionResult> CheckTokenStatus(string jti)
        {
            if (string.IsNullOrEmpty(jti))
            {
                logger.LogWarning("Internal check: Received empty or null JTI.");
                return BadRequest();
            }

            // Пытаемся проверить статус токена
            try
            {
                // IsTokenRevokedAsync возвращает true, если токен отозван или не найден в базе
                bool isRevoked = await tokenRepository.IsTokenRevokedAsync(jti);
                bool isActive = !isRevoked;

                if (isActive)
                {
                    // Используем Debug, чтобы не спамить в логи при каждом запросе каждого сервиса,
                    // так как это штатная ситуация.
                    logger.LogDebug("Internal check: JTI {Jti} is valid and active.", jti);
                }
                else
                {
                    // А вот факт проверки отозванного токена — это уже информация для безопасности.
                    logger.LogInformation("Internal check: JTI {Jti} is REVOKED or not found.", jti);
                }

                return Ok(new { IsActive = isActive });
            }
            catch (Exception ex)
            {
                // Логируем ошибку БД, если она случилась
                logger.LogError(ex, "Error occurred while checking status for JTI {Jti} in database.", jti);
                return StatusCode(500, "Internal error during token validation.");
            }
        }
    }
}