using Microsoft.EntityFrameworkCore;

namespace Dekauto.Auth.Service.Infrastructure;

/// <summary>
/// Создание записи teacher_entities при регистрации преподавателя (общая БД).
/// </summary>
public interface ITeacherProfileProvisioner
{
    Task EnsureTeacherEntityAsync(string externalTeacherId, string displayName, CancellationToken ct = default);
}

public class TeacherProfileProvisioner : ITeacherProfileProvisioner
{
    private readonly DekautoContext context;

    public TeacherProfileProvisioner(DekautoContext context)
    {
        this.context = context;
    }

    public async Task EnsureTeacherEntityAsync(string externalTeacherId, string displayName, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(externalTeacherId))
        {
            return;
        }

        var name = string.IsNullOrWhiteSpace(displayName) ? externalTeacherId : displayName.Trim();
        await context.Database.ExecuteSqlInterpolatedAsync(
            $"""
            INSERT INTO teacher_entities (id, name)
            VALUES ({externalTeacherId.Trim()}, {name})
            ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
            """,
            ct);
    }
}
