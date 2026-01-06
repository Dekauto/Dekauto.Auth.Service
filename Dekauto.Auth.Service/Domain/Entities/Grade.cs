using System;
using System.Collections.Generic;

namespace Dekauto.Auth.Service.Domain.Entities;

public partial class Grade
{
    public Guid Id { get; set; }

    public Guid? StudentId { get; set; }

    public Guid? DisciplineId { get; set; }

    public string? Grade1 { get; set; }

    /// <summary>
    /// Номер семестра
    /// </summary>
    public short? SemesterNumber { get; set; }

    /// <summary>
    /// Год для семестра
    /// </summary>
    public DateOnly? Year { get; set; }

    public virtual Discipline? Discipline { get; set; }

    public virtual Student? Student { get; set; }
}
