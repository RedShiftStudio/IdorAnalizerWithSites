using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;

namespace Site_2.Controllers
{
    public class Profile
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }

        public string Role {  get; set; }
    }

    [ApiController]
    [Route("api/v1/profiles")]
    public class V1ProfilesController : ControllerBase
    {
        private static List<Profile> _profiles = new List<Profile>
        {
            new Profile { Id = 1, Name = "User1", Email = "user1@example.com" },
            new Profile { Id = 2, Name = "User2", Email = "user2@example.com" }
        };

        // ❌ Уязвимый GET (без проверки доступа)
        [HttpGet("{id}")]
        public IActionResult GetProfile(int id)
        {
            var profile = _profiles.FirstOrDefault(p => p.Id == id);
            return Ok(profile);
        }

        // ❌ Уязвимый POST
        [HttpPost("{id}")]
        public IActionResult UpdateProfile(int id, [FromBody] Profile updatedProfile)
        {
            var profile = _profiles.FirstOrDefault(p => p.Id == id);
            return Ok(profile);
        }

        // 9. Parameter Pollution
        [HttpGet("search")]
        public IActionResult Search([FromQuery] string q)
        {
            var profiles = _profiles.Where(p => p.Name.Contains(q) || p.Email.Contains(q));
            return Ok(profiles);
        }

        // 10. Content-Type Manipulation
        [HttpGet("content-type-test")]
        public IActionResult ContentTypeTest()
        {
            return Ok(new { message = "Content-Type test successful" });
        }

        // 11. Static Keywords
        [HttpGet("current")]
        public IActionResult GetCurrent()
        {
            return Ok(_profiles[0]); // Всегда возвращаем первого пользователя
        }
    }
}