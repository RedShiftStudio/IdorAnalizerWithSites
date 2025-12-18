using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;

namespace Site_2.Controllers
{
    [ApiController]
    [Route("api/v2/profiles")]
    public class V2ProfilesController : ControllerBase
    {
        private static List<Profile> _profiles = new List<Profile>
        {
            new Profile { Id = 1, Name = "User1", Email = "user1@example.com" },
            new Profile { Id = 2, Name = "User2", Email = "user2@example.com" }
        };

        // ✅ Защищённый GET (с проверкой доступа)
        [HttpGet("{id}")]
        public IActionResult GetProfile(int id)
        {
            var profile = _profiles.FirstOrDefault(p => p.Id == id);
            if (profile == null) return NotFound();
            if (id != 1) return Forbid(); // Только User1 может читать
            return Ok(profile);
        }

        // ✅ Защищённый POST
        [HttpPost("{id}")]
        public IActionResult UpdateProfile(int id, [FromBody] Profile updatedProfile)
        {
            if (id != 1) return Forbid();
            var profile = _profiles.FirstOrDefault(p => p.Id == id);
            return Ok(profile);
        }
    }
}