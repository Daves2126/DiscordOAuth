using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
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
        if (oauthProviders is null) throw new InvalidOperationException("OAuthProviders is not configured");

        var discordOptions = oauthProviders.Providers["Discord"];
        if (discordOptions is null) throw new InvalidOperationException("Discord OAuth provider is not configured");

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
                foreach (var claim in claims) Console.WriteLine($"Claim: {claim.Type} = {claim.Value}");
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
        if (jwtOptions is null) throw new InvalidOperationException("JwtOptions is not configured");

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = new RsaSecurityKey(LoadRsaKey(jwtOptions.RsaPublicKeyLocation)),
            RequireSignedTokens = true
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

    if (!result.Succeeded) return Results.Unauthorized();

    var jwtOptions = builder.Configuration.GetSection("Jwt").Get<JwtOptions>();
    if (jwtOptions is null) throw new InvalidOperationException("JwtOptions is not configured");

    var claims = result.Principal.Claims.ToList();
    var permissions = new List<string>
    {
        "user-add",
        "user-view"
    };

    claims.AddRange(permissions.Select(permission => new Claim("permissions", permission)));
    
    // Create JWT token
    var tokenString = GenerateJwt(jwtOptions, claims);
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok(new { token = tokenString });
});

app.MapGet("/denied", () => Results.Content("Access Denied", "text/plain"));

app.MapGet("/.well-known/jwks.json", () =>
{
    Console.WriteLine("Serving JWKs");
    var jwtOptions = builder.Configuration.GetSection("Jwt").Get<JwtOptions>();
    if (jwtOptions is null) throw new InvalidOperationException("JwtOptions is not configured");

    var rsaKey = LoadRsaKey(jwtOptions.RsaPublicKeyLocation);
    var rsaParameters = rsaKey.ExportParameters(false);

    var jwk = new JsonWebKey
    {
        Kty = "RSA",
        E = Base64UrlEncoder.Encode(rsaParameters.Exponent),
        N = Base64UrlEncoder.Encode(rsaParameters.Modulus),
        Kid = "vasitos-public-key",
        Use = "sig",
        KeyOps = { "verify" },
        Alg = SecurityAlgorithms.RsaSha256
    };

    var jwks = new
    {
        Keys = new[] { jwk }
    };

    return Results.Json(jwks);
});

app.Run();
return;

static string GenerateJwt(JwtOptions jwtOptions, List<Claim> claims)
{
    var tokenHandler = new JwtSecurityTokenHandler();

    var rsaPath = Path.GetFullPath(jwtOptions.RsaPrivateKeyLocation);
    var rsa = LoadRsaKey(rsaPath);
    var signingCredentials = new SigningCredentials(
        new RsaSecurityKey(rsa),
        SecurityAlgorithms.RsaSha256
    );

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddDays(7),
        Issuer = jwtOptions.Issuer,
        Audience = jwtOptions.Audience,
        SigningCredentials = signingCredentials
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
}

static RSA LoadRsaKey(string rsaKeyPath)
{
    var rsa = RSA.Create();
    if (!File.Exists(rsaKeyPath))
    {
        throw new FileNotFoundException("RSA key file not found", rsaKeyPath);
    }
    var pemContents = File.ReadAllText(rsaKeyPath); 
    rsa.ImportFromPem(pemContents.ToCharArray());

    return rsa;
}
