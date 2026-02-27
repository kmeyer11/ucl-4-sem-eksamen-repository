using Danplanner.Application.Interfaces.AddonInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Microsoft.AspNetCore.Mvc;

namespace Danplanner.Client.Controllers
{
    [ApiController]
    [Route("api/addon/[controller]")]
    public class AddonController : ControllerBase
    {
        private readonly IAddonGetAll _addonGetAll;

        public AddonController(IAddonGetAll addonGetAll)
        {
            _addonGetAll = addonGetAll;
        }

        [HttpGet]
        public async Task<ActionResult<List<AddonDto>>> GetAddons()
        {
            var addons = await _addonGetAll.GetAllAddonsAsync();
            return Ok(addons);
        }
    }

}
