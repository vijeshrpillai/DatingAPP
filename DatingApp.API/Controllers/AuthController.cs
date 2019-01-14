using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _authRepository;
        private readonly IConfiguration config;
        public AuthController(IAuthRepository _authRepository, IConfiguration config)
        {
            this.config = config;
            this._authRepository = _authRepository;

        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(DtoUserForRegister DtoUserForRegister)
        {

            //validation
            // if (!ModelState.IsValid)
            //     return BadRequest(ModelState);

            DtoUserForRegister.username = DtoUserForRegister.username.ToLower();
            if (await _authRepository.IsUserExists(DtoUserForRegister.username))
            {
                return BadRequest("Username already taken");
            }

            var user = await _authRepository.Register(new Models.User { Username = DtoUserForRegister.username }, DtoUserForRegister.password);
            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(DtoUserForLogin DtoUserForLogin)
        {
            var user = await _authRepository.Login(DtoUserForLogin.username.ToLower(), DtoUserForLogin.password);
            if (user == null)
            {
                return Unauthorized();
            }

            var claim = new[]{
                new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
                new Claim(ClaimTypes.Name,user.Username)
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.GetSection("AppSettings:Token").Value));
            var cred= new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);
            var tokenDescriptor= new SecurityTokenDescriptor{
                Subject= new ClaimsIdentity(claim),
                Expires=DateTime.Now.AddDays(1),
                SigningCredentials=cred
            };

            var tokenHandler= new JwtSecurityTokenHandler();
            var token=tokenHandler.CreateToken(tokenDescriptor);

            return Ok(new{token=tokenHandler.WriteToken(token)});
        }
    }
}