using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace ApiVersioningVulnerableApp.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private static readonly Dictionary<string, string> _users = new()
        {
            { "apiuser1", "api1pass" },
            { "apiuser2", "api2pass" }
        };

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            if (_users.TryGetValue(request.Username, out var password) && password == request.Password)
            {
                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, request.Username),
                    new Claim(ClaimTypes.NameIdentifier, request.Username == "apiuser1" ? "1" : "2")
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your-256-bit-secret"));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var token = new JwtSecurityToken(issuer: "test", audience: "test", claims: claims, expires: DateTime.Now.AddHours(1), signingCredentials: creds);

                return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
            }
            return Unauthorized();
        }
    }

    public class LoginRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}