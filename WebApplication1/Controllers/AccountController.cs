using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using WebApplication1.Models;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace WebApplication1.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IConfiguration _configuration;

    public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        if (ModelState.IsValid)
        {
            var user = new ApplicationUser { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return Ok(new { message = "User created successfully" });
            }

            return BadRequest(result.Errors);
        }

        return BadRequest(ModelState);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var user = await _userManager.FindByNameAsync(model.Username);

        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
        {
            var token = GenerateJwtToken(user);
            
            // Добавляем токен в куки
            Response.Cookies.Append("AuthToken", token, new CookieOptions
            {
                Expires = DateTimeOffset.UtcNow.AddMinutes(60) // Время жизни куки
            });
            
            return Ok(new { token });
        }

        return Unauthorized();
    }

    private string GenerateJwtToken(ApplicationUser user)
    {
        // Здесь создается набор утверждений (claims).
        // Утверждения — это ключи и значения, которые описывают пользователя. В данном случае:
        // JwtRegisteredClaimNames.Sub:
        // это утверждение о том, кто является субъектом токена — в данном случае это имя пользователя (user.UserName).
        // JwtRegisteredClaimNames.Jti:
        // это уникальный идентификатор токена, чтобы каждый токен был уникальным (генерируется с помощью Guid).
        // ClaimTypes.NameIdentifier:
        // это идентификатор пользователя (user.Id), который может понадобиться серверу для того, чтобы однозначно идентифицировать пользователя.
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id)
        };
        
        
        // Здесь создается секретный ключ, который будет использоваться для подписи токена,
        // чтобы его нельзя было подделать. Ключ берется из конфигурации (_configuration["Jwt:Key"])
        // и кодируется в байты.
        //
        //Токен подписывается с использованием алгоритма HMAC-SHA256 (SecurityAlgorithms.HmacSha256).
        //Это делает токен защищенным от изменений: если кто-то попробует его изменить, сервер не примет его,
        //потому что подпись будет недействительной.
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // Создаем токен с указанными данными
        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],          // Издатель токена
            audience: _configuration["Jwt:Audience"],      // Аудитория токена
            claims: claims,                                 // Заявки (claims)
            expires: DateTime.Now.AddMinutes(60),          // Время жизни токена
            signingCredentials: creds                        // Подпись токена
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}