using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AspNet.Security.OAuth.Discord;
using DiscordOauth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddAuthorization();
builder.Configuration.AddEnvironmentVariables();
builder.Configuration.AddUserSecrets<Program>();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = DiscordAuthenticationDefaults.AuthenticationScheme;
    })
    .AddDiscord(options =>
    {
        var oauthProviders = builder.Configuration.GetSection("OAuthProviders").Get<OAuthProviders>();
        if (oauthProviders is null)
        {
            throw new InvalidOperationException("OAuthProviders is not configured");
        }

        var discordOptions = oauthProviders.Providers["Discord"];
        if (discordOptions is null)
        {
            throw new InvalidOperationException("Discord OAuth provider is not configured");
        }
        
        options.ClientId = discordOptions.ClientId;
        options.ClientSecret = discordOptions.ClientSecret;
        options.CallbackPath = discordOptions.CallBack;
        options.SaveTokens = true;
        
        options.CorrelationCookie.SameSite = SameSiteMode.Lax;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        
        options.ClaimActions.MapCustomJson("urn:discord:avatar:url", user =>
            string.Format(
                CultureInfo.InvariantCulture,
                "https://cdn.discordapp.com/avatars/{0}/{1}.{2}",
                user.GetString("id"),
                user.GetString("avatar"),
                user.GetString("avatar")!.StartsWith("a_") ? "gif" : "png"));
        
        options.Scope.Add("identify");
        options.Scope.Add("email");

        options.Events = new OAuthEvents
        {
            OnTicketReceived = context =>
            {
                Console.WriteLine("Ticket received from Discord");
                var claims = context.Principal?.Claims ?? Array.Empty<Claim>();
                foreach (var claim in claims)
                {
                    Console.WriteLine($"Claim: {claim.Type} = {claim.Value}");
                }
                return Task.CompletedTask;
            }
        };
    })
    .AddCookie(options =>
    {
        options.Cookie.Name = "DiscordAuth";
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    })
    .AddJwtBearer(options =>
    {
        var jwtOptions = builder.Configuration.GetSection("Jwt").Get<JwtOptions>();
        if (jwtOptions is null)
        {
            throw new InvalidOperationException("JwtOptions is not configured");
        }
        
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Key))
        };
    });

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/login", () => 
{
    var properties = new AuthenticationProperties 
    { 
        RedirectUri = "/get-token",
        IsPersistent = true
    };
    
    return Results.Challenge(properties, [DiscordAuthenticationDefaults.AuthenticationScheme]);
});

app.MapGet("/get-token", async (HttpContext context) =>
{
    var result = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    
    if (!result.Succeeded)
    {
        return Results.Unauthorized();
    }

    var jwtOptions = builder.Configuration.GetSection("Jwt").Get<JwtOptions>();
    if (jwtOptions is null)
    {
        throw new InvalidOperationException("JwtOptions is not configured");
    }
    
    var claims = result.Principal.Claims.ToList();
    
    // Create JWT token
    var tokenString = GenerateJwt(jwtOptions, claims);
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok(new { token = tokenString });
});

app.MapGet("/denied", () => Results.Content("Access Denied", "text/plain"));

app.Run();
return;

static string GenerateJwt(JwtOptions jwtOptions, List<Claim> list)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.UTF8.GetBytes(jwtOptions.Key);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(list),
        Expires = DateTime.UtcNow.AddDays(7),
        Issuer = jwtOptions.Issuer,
        Audience = jwtOptions.Audience,
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha256Signature)
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
}
