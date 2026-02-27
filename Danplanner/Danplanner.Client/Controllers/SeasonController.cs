using Danplanner.Application.Interfaces.ConfirmationInterfaces;
using Danplanner.Application.Interfaces.SeasonInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

[ApiController]
[Route("api/[controller]")]
public class SeasonController : ControllerBase
{
    private readonly ISeasonGetForDate _seasonGetForDate;
    private readonly ISeasonGetAll _seasonGetAll;

    public SeasonController(ISeasonGetForDate seasonGetForDate, ISeasonGetAll seasonGetAll)
    {
        _seasonGetForDate = seasonGetForDate;
        _seasonGetAll = seasonGetAll;
    }

    [HttpGet("date/{date}")]
    public async Task<ActionResult<SeasonDto>> GetSeasonForDate(DateTime date)
    {
        var season = await _seasonGetForDate.GetSeasonForDate(date);
        if (season == null) return NotFound();
        return Ok(season);
    }

    [HttpGet]
    public async Task<ActionResult<List<SeasonDto>>> GetAllSeasons()
    {
        var seasons = await _seasonGetAll.GetAllSeasonsAsync();
        return Ok(seasons);
    }
}
