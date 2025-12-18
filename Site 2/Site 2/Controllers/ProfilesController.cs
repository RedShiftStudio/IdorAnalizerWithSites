using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace Site_2.Controllers
{

    [ApiController]
    public class ProfileController : ControllerBase
    {
        protected static readonly List<Profile> _profiles = new List<Profile>
        {
            new Profile { Id = 1, Name = "API User 1", Email = "apiuser1@example.com", Role = "user" },
            new Profile { Id = 2, Name = "API User 2", Email = "apiuser2@example.com", Role = "user" },
            new Profile { Id = 100, Name = "Admin", Email = "admin@example.com", Role = "admin" }
        };

        protected Profile? GetUserFromToken()
        {
            var userId = User.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;
            if (userId != null && int.TryParse(userId, out int id))
            {
                return _profiles.FirstOrDefault(p => p.Id == id);
            }
            return null;
        }
    }
}