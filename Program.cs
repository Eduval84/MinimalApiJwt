using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using MinimalApiJwt.Entities;
using MinimalApiJwt.Models;
using MinimalApiJwt.Persistance;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

/// <summary>
/// Para configurar Identity y EntityFramework, registramos las siguientes dependencias
/// </summary>
/// AddSqlite: Registra el DbContext, es un atajo del método habitual AddDbContext
/// AddIdentityCore: Registra las dependencias que necesita Identity, como generador de contraseñas, manejo de usuarios, etc
/// AddRoles: Registra todo lo necesario para poder usar roles (en este caso, con la implementación default de la clase IdentityRole)
/// Vincula nuestro contexto de EntityFramework con todas sus dependencias que Identity necesita respecto a persistencia
builder.Services
    .AddSqlite<DbContext>(builder.Configuration.GetConnectionString("Default"))  
    .AddIdentityCore<User>() 
    .AddRoles<IdentityRole>() 
    .AddEntityFrameworkStores<DbContext>();

/// <summary>
/// Agregamos la configuración que necesitamos para poder autenticar por medio de JWTs
/// </summary>
/// AddHttpContextAccessor: Registra el IHttpContextAccessor que nos permite acceder el HttpContextde cada solicitud (la usaremos más adelante para acceder al usuario actual autenticado)
/// AddAutorization: Dependencias necesarias para autorizar solicitudes (como autorización por roles)
/// AddAuthentication: Agrega el esquema de autenticación que queramos usar, en este caso, queremos usar por default la autenticación por Bearer Tokens
/// AddJwtBearer: Configura la autenticación por tokens, especificando que debe de validar y que llave privada utilizar
/// Por supuesto, esta configuración la va a leer del appsettings.json
builder.Services
    .AddHttpContextAccessor()
    .AddAuthorization()
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello World!");

app.Run();



app.MapPost("/token", async (AuthenticateRequest request, UserManager<User> userManager) =>
{
    // Verificamos credenciales con Identity
    var user = await userManager.FindByNameAsync(request.UserName);

    if (user is null || !await userManager.CheckPasswordAsync(user, request.Password))
    {
        return Results.Forbid();
    }

    var roles = await userManager.GetRolesAsync(user);

    // Generamos un token según los claims
    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Sid, user.Id),
        new Claim(ClaimTypes.Name, user.UserName),
        new Claim(ClaimTypes.GivenName, $"{user.FirstName} {user.LastName}")
    };

    foreach (var role in roles)
    {
        claims.Add(new Claim(ClaimTypes.Role, role));
    }

    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]));
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
    var tokenDescriptor = new JwtSecurityToken(
        issuer: builder.Configuration["Jwt:Issuer"],
        audience: builder.Configuration["Jwt:Audience"],
        claims: claims,
        expires: DateTime.Now.AddMinutes(720),
        signingCredentials: credentials);

    var jwt = new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);

    return Results.Ok(new
    {
        AccessToken = jwt
    });

    app.MapGet("/me", (IHttpContextAccessor contextAccessor) =>
    {
        var user = contextAccessor.HttpContext.User;

        return Results.Ok(new
        {
            Claims = user.Claims.Select(s => new
            {
                s.Type,
                s.Value
            }).ToList(),
            user.Identity.Name,
            user.Identity.IsAuthenticated,
            user.Identity.AuthenticationType
        });
    })
    .RequireAuthorization();

});

