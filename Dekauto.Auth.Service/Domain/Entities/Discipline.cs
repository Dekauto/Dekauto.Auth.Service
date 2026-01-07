using System;
using System.Collections.Generic;

namespace Dekauto.Auth.Service.Domain.Entities;

public partial class Discipline
{
    public Guid Id { get; set; }

    /// <summary>
    /// Название дисциплины
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Зачетные единицы
    /// </summary>
    public decimal? CreditUnits { get; set; }

    /// <summary>
    /// Академические часы
    /// </summary>
    public decimal? AcademicHours { get; set; }

    /// <summary>
    /// зачет, зачет с оценкой, экзамен, курсовая, практика
    /// </summary>
    public string? Type { get; set; }

    public virtual Grade? Grade { get; set; }
}
