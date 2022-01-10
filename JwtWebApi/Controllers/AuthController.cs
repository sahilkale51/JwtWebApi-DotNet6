using JwtWebApi.Data;
using JwtWebApi.Dtos;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly DataContext _context;
        private readonly IConfiguration _configuration;

        public AuthController(DataContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreateHashedPassword(request.Password, out byte[] PasswordHash, out byte[] PasswordSalt);
            var user = new User
            {
                userName = request.UserName,
                passwordHash = PasswordHash,
                passwordSalt = PasswordSalt
            };

            await _context.Users.AddAsync(user);
            _context.SaveChanges();
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            var user = await _context.Users.FindAsync(request.Id);

            if(user == null)
            {
                return BadRequest("User not found");
            }

            if (user.userName != request.UserName)
            {
                return BadRequest("Wrong UserName");
            }

            if (!VerifyPassword(request.Password, user.passwordHash, user.passwordSalt))
            {
                return BadRequest("Wrong Password");
            }


            var token = CreateToken(user);

            return Ok(token);
        }

        private string CreateToken(User user)
        {

            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.userName),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:token").Value));
            var creds = new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims : claims,
                expires : DateTime.Now.AddDays(1),
                signingCredentials : creds
                );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }

        private void CreateHashedPassword(string password, out byte[] passwordhash, out byte[] passwordsalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordsalt = hmac.Key;
                passwordhash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPassword(string password,byte[] passwordhash, byte[] passwordsalt)
        {
            using(var hmac = new HMACSHA512(passwordsalt))
            {
                var hashedPassword = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return passwordhash.SequenceEqual(hashedPassword);
            }
        }


    }
}
