using Athentications.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;


namespace Athentications.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AthenticateController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AthenticateController(IConfiguration configuration)
        {
            _configuration = configuration;
        }



        public static User user = new User();

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            user.UserName = request.UserName;
            user.PasswordHash = passwordHash;

            return Ok(user);


        }

        [HttpPost("login")]
        public ActionResult<User> Login(UserDto request)
        {
            if (user.UserName != request.UserName)
            {
                return BadRequest("The User NOt Found");
            }


            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                return BadRequest("Wrong Password");
            }
            string token = CreateToken(user);
            return Ok(token);


        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
    {
        new Claim(ClaimTypes.Name, user.UserName)
    };

            var key = GenerateSymmetricKey(512);
            var symmetricSecurityKey = new SymmetricSecurityKey(key);

            var cereds = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cereds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }

        private byte[] GenerateSymmetricKey(int keySize)
        {
            using (var generator = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                var key = new byte[keySize / 8];
                generator.GetBytes(key);
                return key;
            }
        }

    }
}
