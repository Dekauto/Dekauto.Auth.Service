using Dekauto.Auth.Service.Domain.Entities.DTO;
using Dekauto.Auth.Service.Domain.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Authentication;

namespace Dekauto.Auth.Service.Controllers
{
    /// <summary>
    /// КОНТРОЛЛЕР УПРАВЛЕНИЯ ПОЛЬЗОВАТЕЛЯМИ И СЕССИЯМИ
    /// </summary>
    /// <remarks>
    /// Этот контроллер предоставляет администраторам инструменты для управления пользователями, их сессиями и паролями.
    /// Все операции требуют прав администратора и авторизации через JWT токен.
    /// </remarks>
    [Route("api")]
    [ApiController]
    [Authorize(Policy = "OnlyAdmin")]
    public class UserManagementController : ControllerBase
    {
        private readonly IUserManagementService userManagementService;
        private readonly IUserAuthServiceDb userAuthService;
        private readonly IConfiguration configuration;
        private readonly ILogger<UserManagementController> logger;

        public UserManagementController(IUserManagementService userManagementService, ILogger<UserManagementController> logger,
            IUserAuthServiceDb userAuthService, IConfiguration configuration)
        {
            this.userManagementService = userManagementService;
            this.logger = logger;
            this.userAuthService = userAuthService;
            this.configuration = configuration;
        }

        /// <summary>
        /// Изменить пароль пользователя (стандартный способ)
        /// </summary>
        /// <remarks>
        /// ## Описание
        /// Изменяет пароль пользователя. Требует знания текущего пароля.
        /// 
        /// ## Что происходит после смены
        /// 1. Пароль хэшируется и сохраняется в БД
        /// 2. Все активные сессии остаются действительными
        /// 3. Для следующих входов используется новый пароль
        /// 
        /// ## Если текущий пароль неизвестен
        /// Используйте **принудительную смену пароля**, если она включена в настройках.
        /// </remarks>
        /// <param name="login">Идентификатор пользователя (GUID)</param>
        /// <param name="newPassword">Новый пароль пользователя</param>
        /// <param name="currentPassword">Текущий пароль пользователя</param>
        /// <response code="200">Пароль успешно изменен</response>
        /// <response code="400">Неверные параметры запроса</response>
        /// <response code="403">Неверный текущий пароль</response>
        /// <response code="500">Внутренняя ошибка сервера</response>
        [HttpPost("{login}/changepass")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        [ProducesResponseType(500)]
        public async Task<IActionResult> UpdateUserPasswordAsync(string login, string newPassword, string currentPassword)
        {
            try
            {
                if (string.IsNullOrEmpty(newPassword))
                {
                    throw new ArgumentException($"'{nameof(newPassword)}' cannot be null or empty.", nameof(newPassword));
                }

                if (string.IsNullOrEmpty(currentPassword))
                {
                    throw new ArgumentException($"'{nameof(currentPassword)}' cannot be null or empty.", nameof(currentPassword));
                }

                await userAuthService.ChangePasswordAsync(login, newPassword, currentPassword);

                logger.LogInformation($"Password for user {login} has been changed.");
                return Ok();

            }
            catch (InvalidCredentialException ex)
            {
                logger.LogError(ex, "Invalid password.");
                return StatusCode(StatusCodes.Status403Forbidden, "Указан неверный пароль.");
            }
            catch (ArgumentException ex)
            {
                logger.LogError(ex, "Not enough arguments passed to change the password");
                return StatusCode(StatusCodes.Status400BadRequest,
                    "Возникла непредвиденная ошибка при изменении пароля. Обратитесь к администратору или попробуйте позже.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An unexpected error occurred while changing the password");
                return StatusCode(StatusCodes.Status500InternalServerError,
                    "Возникла непредвиденная ошибка при изменении пароля. Обратитесь к администратору или попробуйте позже.");
            }
        }

        /// <summary>
        /// Проверить доступность принудительной смены пароля
        /// </summary>
        /// <remarks>
        /// ## Описание
        /// Проверяет, включена ли возможность принудительной смены пароля без знания текущего пароля.
        /// 
        /// ## Как включить принудительную смену пароля
        /// 1. Откройте файл `.env` на сервере
        /// 2. Найдите переменную `AUTH_FORCE_PASS_CHANGE`
        /// 3. Измените значение на `true`
        /// 4. Перезапустите сервис: `docker compose restart Dekauto.auth`
        /// 5. Обновите страницу Swagger
        /// 6. Выполните этот запрос для проверки доступности
        /// 
        /// ## Когда использовать
        /// - **Потерян пароль администратора** - экстренный доступ к системе
        /// - **Уволенный сотрудник** - смена пароля без его участия
        /// - **Восстановление системы** - после сбоев или атак
        /// 
        /// ## Примеры ответов
        /// ```json
        /// true   // Функция доступна
        /// false  // Функция недоступна
        /// ```
        /// 
        /// ## Важное предупреждение
        /// ⚠️ **ЭКСТРЕННАЯ ФУНКЦИЯ** - используйте только в критических ситуациях!
        /// 
        /// После использования:
        /// 1. Верните `AUTH_FORCE_PASS_CHANGE=false` в `.env`
        /// 2. Перезапустите сервис
        /// 3. Проверьте логи на подозрительную активность
        /// </remarks>
        /// <returns>true - если функция доступна, false - если недоступна</returns>
        /// <response code="200">Успешно возвращен статус доступности</response>
        [HttpGet("changepass/force/available")]
        [ProducesResponseType(typeof(bool), 200)]
        public IActionResult IsForcePasswordChangeAvailable()
        {
            var isAvailable = configuration.GetValue<bool>("AllowForcePasswordChange", false);
            return Ok(isAvailable);
        }

        /// <summary>
        /// Принудительная смена пароля (экстренный доступ)
        /// </summary>
        /// <remarks>
        /// ## Описание
        /// Позволяет изменить пароль пользователя **без знания текущего пароля**.
        /// Требует предварительного включения функции в настройках.
        /// 
        /// ## Условия использования
        /// ✅ **Доступно без авторизации** - не требует токена
        /// ✅ **Не требует текущего пароля** - меняет напрямую
        /// ✅ **Сессии остаются** - пользователь не разлогинивается
        /// ❌ **Требует настройки** - нужно включить в `.env`
        /// 
        /// ## Пошаговая инструкция:
        /// 1. Включите функцию в `.env`: `AUTH_FORCE_PASS_CHANGE=true`
        /// 2. Перезапустите сервис
        /// 3. Проверьте доступность: `GET /api/changepass/force/available`
        /// 4. Найдите ID пользователя: `GET /api/users`
        /// 5. Выполните этот запрос с новым паролем
        /// 6. **Немедленно отключите функцию!**
        /// 
        /// ## Ответ при успехе
        /// ```json
        /// {
        ///   "message": "Пароль успешно изменен"
        /// }
        /// ```
        /// 
        /// ## Что происходит
        /// 1. Пароль изменяется без проверки текущего
        /// 2. Все активные сессии остаются действительными
        /// 3. Операция логируется с пометкой `FORCE_PASSWORD_CHANGE`
        /// 4. Пользователь может войти с новым паролем
        /// 
        /// ## После смены пароля:
        /// 1. Войдите в систему с новым паролем
        /// 2. Проверьте активные сессии пользователя
        /// 3. При необходимости отзовите все сессии
        /// 4. Верните стандартные настройки безопасности
        /// 
        /// ## Ошибки
        /// - `403 Forbidden` - функция не включена в настройках
        /// - `404 Not Found` - пользователь не найден
        /// - `400 Bad Request` - неверный формат пароля
        /// </remarks>
        /// <param name="login">Логин пользователя</param>
        /// <param name="newPassword">Новый пароль пользователя</param>
        /// <response code="200">Пароль успешно изменен</response>
        /// <response code="400">Неверные параметры запроса</response>
        /// <response code="403">Функция принудительной смены недоступна</response>
        /// <response code="404">Пользователь не найден</response>
        /// <response code="500">Внутренняя ошибка сервера</response>
        [AllowAnonymous]
        [HttpPost("{login}/changepass/force")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        public async Task<IActionResult> ForceUpdateUserPasswordAsync(string login, string newPassword)
        {
            try
            {
                if (string.IsNullOrEmpty(newPassword))
                {
                    throw new ArgumentException($"'{nameof(newPassword)}' cannot be null or empty.", nameof(newPassword));
                }

                await userAuthService.ChangePasswordAsync(login, newPassword, null, true);

                logger.LogInformation($"Password for user {login} has been forcefully changed.");
                return Ok(new { Message = $"Пароль для пользователя {login} был принудительно изменен." });

            }
            catch (InvalidOperationException ex)
            {
                logger.LogError(ex, "Force password update is not available.");
                return StatusCode(StatusCodes.Status403Forbidden,
                    "Принудительная смена пароля недоступна.");
            }
            catch (KeyNotFoundException ex)
            {
                logger.LogError(ex, "User not found");
                return StatusCode(StatusCodes.Status500InternalServerError,
                    "Пользователь не найден.");
            }
            catch (InvalidCredentialException ex)
            {
                logger.LogError(ex, "Invalid password.");
                return StatusCode(StatusCodes.Status403Forbidden, "Указан неверный пароль.");
            }
            catch (ArgumentException ex)
            {
                logger.LogError(ex, "Not enough arguments passed to change the password");
                return StatusCode(StatusCodes.Status400BadRequest,
                    "Возникла непредвиденная ошибка при изменении пароля. Обратитесь к администратору или попробуйте позже.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An unexpected error occurred while changing the password");
                return StatusCode(StatusCodes.Status500InternalServerError,
                    "Возникла непредвиденная ошибка при изменении пароля. Обратитесь к администратору или попробуйте позже.");
            }
        }

        /// <summary>
        /// Получить все активные сессии пользователя (включая JTI)
        /// </summary>
        /// <remarks>
        /// ## Описание
        /// Возвращает список всех активных сессий (JWT токенов) для указанного пользователя.
        /// 
        ///  ## Пример ответа:
        /// ```json
        /// [
        ///   {
        ///     "jti": "550e8400-e29b-41d4-a716-446655440000",
        ///     "userId": "123e4567-e89b-12d3-a456-426614174000",
        ///     "createdAt": "2024-01-15T10:30:00Z",
        ///     "expiresAt": "2024-01-15T18:30:00Z",
        ///     "deviceInfo": "Chrome 120.0, Windows 10",
        ///     "ipAddress": "192.168.1.100",
        ///     "isActive": true
        ///     "revokeReason": "Причина отзыва сессии"
        ///   }
        /// ]
        /// ```
        /// ## Примечание
        /// deviceInfo и ipAddress на данный момент недоступны и будут показывать только Unknown.
        /// </remarks>
        /// <param name="login">Логин пользователя</param>
        /// <returns>Список активных сессий пользователя</returns>
        /// <response code="200">Успешно возвращен список сессий</response>
        /// <response code="401">Требуется авторизация администратора</response>
        /// <response code="403">Недостаточно прав (требуется роль администратора)</response>
        /// <response code="500">Внутренняя ошибка сервера</response>
        [HttpGet("users/{login}/sessions")]
        [ProducesResponseType(typeof(IEnumerable<UserSessionDto>), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(403)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        public async Task<IActionResult> GetUserSessions(string login)
        {
            try
            {
                var sessions = await userManagementService.GetUserSessionsAsync(login);
                return Ok(sessions);
            }
            catch (KeyNotFoundException ex)
            {
                logger.LogWarning(ex, $"No user {login} exists");
                return StatusCode(404, $"Пользователя {login} не существует.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Error getting sessions for user {login}");
                return StatusCode(500, "Ошибка при получении списка сессий.");
            }
        }


        /// <summary>
        /// Отозвать конкретную сессию
        /// </summary>
        /// <remarks>
        /// ## Описание
        /// Отзывает только одну конкретную сессию по её JTI (JWT ID), не затрагивая другие сессии пользователя.
        /// 
        /// ## Как найти JTI сессии
        /// 1. Получите список сессий пользователя: `GET /api/users/{userId}/sessions`
        /// 2. Найдите нужную сессию в списке
        /// 3. Скопируйте значение поля `jti`
        /// 
        /// ## Ответ при успехе
        /// ```json
        /// {
        ///   "message": "Сессия успешно отозвана."
        /// }
        /// ```
        /// 
        /// ## Логирование
        /// В системные логи будет добавлена запись:
        /// `Сессия {jti} была отозвана вручную администратором {adminLogin}`
        /// </remarks>
        /// <param name="jti">JWT ID (JTI) токена сессии</param>
        /// <response code="200">Сессия успешно отозвана</response>
        /// <response code="401">Требуется авторизация администратора</response>
        /// <response code="403">Недостаточно прав</response>
        /// <response code="404">Сессия не найдена</response>
        /// <response code="500">Внутренняя ошибка сервера</response>
        [HttpPost("sessions/{jti}/revoke")]
        [ProducesResponseType(typeof(ActionResult), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(403)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
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

        /// <summary>
        /// Отозвать все сессии пользователя
        /// </summary>
        /// <remarks>
        /// ## Описание
        /// Немедленно прекращает все активные сессии пользователя. Пользователь будет разлогинен со всех устройств.
        /// 
        /// ## Сценарии использования
        /// 1. **Увольнение сотрудника** - немедленный отзыв доступа
        /// 2. **Утеря устройства** - предотвращение несанкционированного доступа
        /// 3. **Обнаружение взлома** - экстренное прекращение сессий
        /// 4. **Смена пароля** - при подозрении на компрометацию
        /// 
        /// ## Что происходит
        /// 1. Все JWT токены пользователя помечаются как недействительные
        /// 2. Пользователя немедленно разлогинивает со всех устройств
        /// 3. Для нового входа потребуется повторная авторизация
        /// 
        /// ## Ответ при успехе
        /// ```json
        /// {
        ///   "message": "Все сессии пользователя успешно отозваны."
        /// }
        /// ```
        /// 
        /// ## Логирование
        /// В системные логи будет добавлена запись:
        /// `Все сессии пользователя {userId} были отозваны администратором {adminLogin}`
        /// </remarks>
        /// <param name="login">Логин пользователя</param>
        /// <response code="200">Все сессии успешно отозваны</response>
        /// <response code="401">Требуется авторизация администратора</response>
        /// <response code="403">Недостаточно прав</response>
        /// <response code="404">Пользователь не найден</response>
        /// <response code="500">Внутренняя ошибка сервера</response>
        [HttpPost("users/{login}/revoke-all")]
        [ProducesResponseType(typeof(ActionResult), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(403)]
        [ProducesResponseType(404)]
        [ProducesResponseType(500)]
        public async Task<IActionResult> RevokeAllUserSessions(string login)
        {
            try
            {
                var adminLogin = User.Identity?.Name ?? "Admin";
                var reason = $"Revoked by administrator {adminLogin}";

                await userManagementService.RevokeAllUserSessionsAsync(login, reason);

                logger.LogInformation($"All sessions for user {login} were revoked by {adminLogin}.");
                return Ok(new { Message = "Все сессии пользователя успешно отозваны." });
            }
            catch (KeyNotFoundException ex)
            {
                logger.LogWarning(ex, $"No user {login} exists");
                return StatusCode(404, $"Пользователя {login} не существует.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Error revoking all sessions for user {login}");
                return StatusCode(500, "Ошибка при отзыве сессий.");
            }
        }

        /// <summary>
        /// 🚨 МАССОВЫЙ ОТЗЫВ ВСЕХ СЕССИЙ В СИСТЕМЕ
        /// </summary>
        /// <remarks>
        /// **⚠️ ВНИМАНИЕ: КРИТИЧЕСКАЯ ОПЕРАЦИЯ!**
        ///
        /// Отзывает **ВСЕ активные сессии всех пользователей** в системе. Все пользователи будут немедленно разлогинены.
        ///
        /// **🎯 КОГДА ИСПОЛЬЗОВАТЬ:**
        ///
        /// - **🚨 КРИТИЧЕСКАЯ УЯЗВИМОСТЬ** - обнаружена серьезная уязвимость в системе безопасности
        /// - **🚨 МАССОВАЯ АТАКА** - система подверглась компрометации или DDoS-атаке
        /// - **🚨 ЧРЕЗВЫЧАЙНАЯ СИТУАЦИЯ** - необходимо немедленно остановить всю активность
        /// - **🚨 СМЕНА КЛЮЧЕЙ БЕЗОПАСНОСТИ** - после ротации JWT ключей
        ///
        /// **🔒 ЧТО ПРОИСХОДИТ:**
        ///
        /// 1. **Все пользователи** немедленно разлогиниваются со всех устройств
        /// 2. **Все активные JWT токены** помечаются как недействительные
        /// 3. **Все API запросы** с существующими токенами начинают получать 401 ошибку
        /// 4. **Для нового входа** каждому пользователю потребуется повторная авторизация
        ///
        /// **📊 ЧТО БУДЕТ ЗАТРОНУТО:**
        ///
        /// - **👥 Все пользователи** (администраторы, модераторы, обычные пользователи)
        /// - **📱 Все устройства** (компьютеры, телефоны, планшеты)
        /// - **🌐 Все браузеры** (Chrome, Firefox, Safari, Edge)
        /// - **🕐 Все временные зоны** независимо от времени активности
        /// - **❗ Текущая сессия администратора** - сюда необходимо будет авторизоваться заново
        ///
        /// **⚠️ ПОСЛЕДСТВИЯ:**
        ///
        /// - **Сайты** - пользователей перенесет на страницу авторизации при следующем взаимодествии с системой
        /// - **Активные операции** - могут быть прерваны на середине выполнения
        ///
        /// **✅ ПОДТВЕРЖДЕНИЕ ОПЕРАЦИИ:**
        ///
        /// После выполнения вы получите ответ:
        ///
        /// ```
        /// {
        ///   "message": "ВСЕ сессии в системе успешно отозваны."
        /// }
        /// ```
        ///
        /// **💡 СОВЕТ:** Перед выполнением этой операции убедитесь, что у вас есть рабочий токен администратора для последующего входа.
        /// </remarks>
        /// <response code="200">✅ Успешно. Все сессии отозваны</response>
        /// <response code="401">❌ Не авторизован. Требуется токен администратора</response>
        /// <response code="403">⛔ Запрещено. Нет прав администратора</response>
        /// <response code="500">🔥 Внутренняя ошибка сервера. Проверьте логи</response>
        [HttpPost("users/revoke-all")]
        [ProducesResponseType(typeof(ActionResult), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(403)]
        [ProducesResponseType(500)]
        public async Task<IActionResult> RevokeAllSessions()
        {
            try
            {
                var adminLogin = User.Identity?.Name ?? "Admin";
                var reason = $"Mass revoked by administrator {adminLogin}";

                await userManagementService.RevokeAllSessionsAsync(reason);

                logger.LogInformation($"ALL sessions were revoked by {adminLogin}.");
                return Ok(new { Message = "ВСЕ сессии в системе успешно отозваны." });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Error revoking ALL sessions");
                return StatusCode(500, "Ошибка при отзыве ВСЕХ сессий.");
            }
        }
    }
}