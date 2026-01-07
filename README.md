# Dekauto: ⚪ Сервис Авторизации (Dekauto.Auth.Service)
### Сервис управления учетными записями пользователей, осуществления входа и выдачи токенов для входа. Необходим для доступа к эндпоинтам сервисов [Студенты](https://github.com/TOXYGENCY/Dekauto.Students.Service), [Импорт](https://github.com/TOXYGENCY/Dekauto.Import.Service) и [Экспорт](https://github.com/TOXYGENCY/Dekauto.Export.Service)

### 🔸 Функции 
- Управление (CRUD) объектами User, Role.
- Идентификация, аутентификация и авторизация пользователя.
- Выдача Access-токена (JWT).
- Выдача Refresh-токена и хранение (в памяти).
- Обновление токенов.
- Доступ к панели управления пользователями для администратора по адресу `/swagger/index.html`.
- Подробная документация и понятные инструкции в панели управления.

### 🛠 Технологии
- Git
- .NET 8 (ASP.NET Core 8)
- OpenAPI Swagger
- PostgreSQL 17 (+ Entity Framework Core)
- Grafana Loki + Promtail + Prometheus (логирование и метрики)
- Docker
- CI (GitHub Actions)

## ❇ API-справка
> Расположен на портах `5507 (HTTP)` и `5508 (HTTPS)`

### Контроллер: UserManagement (требует роль Admin)

| Метод | Эндпоинт | Метод контроллера | Описание |
|-------|----------|-------------------|----------|
| `GET` | `api/changepass/force/available` | **IsForcePasswordChangeAvailable** | Проверка доступности принудительной смены пароля |
| `GET` | `api/users/{login}/sessions` | **GetUserSessions** | Получение всех активных сессий пользователя (включая JTI) |
| `POST` | `api/{login}/changepass` | **UpdateUserPasswordAsync** | Смена пароля (требует текущий пароль) |
| `POST` | `api/{login}/changepass/force` | **ForceUpdateUserPasswordAsync** | Принудительная смена пароля (без знания текущего) |
| `POST` | `api/sessions/{jti}/revoke` | **RevokeSession** | Отзыв конкретной сессии по JTI |
| `POST` | `api/users/{login}/revoke-all` | **RevokeAllUserSessions** | Отзыв всех сессий пользователя |
| `POST` | `api/users/revoke-all` | **RevokeAllSessions** | Массовый отзыв ВСЕХ сессий в системе (критическая операция) |

### Контроллер: Users (требует роль Admin)

| Метод | Эндпоинт | Метод контроллера | Описание |
|-------|----------|-------------------|----------|
| `GET` | `api/users` | **GetAllUsersAsync** | Список всех пользователей |
| `GET` | `api/users/{userId}` | **GetUserByIdAsync** | Пользователь по GUID |
| `PUT` | `api/users/{userId}` | **UpdateUserAsync** | Обновление данных пользователя (+ опционально пароль) |
| `DELETE` | `api/users/{userId}` | **DeleteUserAsync** | Удаление пользователя по GUID |
| `POST` | `api/users` | **AddUserAsync** | Добавление нового пользователя (с паролем) |

### Контроллер: Auth (аутентификация)

| Метод | Эндпоинт | Метод контроллера | Описание |
|-------|----------|-------------------|----------|
| `POST` | `api/auth` | **AuthenticateAndGetTokensAsync** | Вход (логин/пароль). Возвращает access-токен + устанавливает refreshToken в cookie |
| `POST` | `api/auth/{userId}/refresh` | **RefreshTokensAsync** | Обновление access-токена через refreshToken (из cookie) |
| `GET` | `api/auth/validate` | **ValidateAccessToken** | Проверка валидности access-токена (требует авторизации) |


---
># ℹ О Dekauto.
>### Что такое Dekauto?
>Dekauto - это web-сервис, направленный на автоматизацию некоторых процессов работы деканата высшего учебного заведения. На данный момент система специализирована для работы в определенном ВУЗе и исполняет функции хранения, агрегации и вывода данных студентов. Ввод осуществляется через Excel-файлы определенного формата. Выводом является Excel-файл карточки студента с заполненными данными. 
>
>### Общая структура Dekauto
>* ⚪ [Dekauto.Auth.Service](https://github.com/TOXYGENCY/Dekauto.Auth.Service) - Сервис управления аккаунтами и входом. _(Вы здесь)_
>    * DockerHub-образ: `toxygency/dekauto_auth_service:release`
>* 🔵 [Dekauto.Students.Service](https://github.com/TOXYGENCY/Dekauto.Students.Service) - Сервис управления Студентами.
>    * DockerHub-образ: `toxygency/dekauto_students_service:release`
>* 🟣 [Dekauto.Import.Service](https://github.com/TOXYGENCY/Dekauto.Import.Service) - Сервис парсинга Excel-файлов для импорта.
>    * DockerHub-образ: `toxygency/dekauto_import_service:release`
>* 🟢 [Dekauto.Export.Service](https://github.com/TOXYGENCY/Dekauto.Export.Service) - Сервис формирования выходного Excel-файла.
>    * DockerHub-образ: `toxygency/dekauto_export_service:release`
>* 🟠 [Dekauto.Angular.Frontend](https://github.com/TOXYGENCY/Dekauto.Angular.Frontend) - Фронтенд: Web-приложение на Angular v19 + NGINX.
>    * DockerHub-образ: `toxygency/dekauto_frontend_nginx:release`
