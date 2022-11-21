using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection.KeyManagement.Internal;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;
using Prezentacja;
using StackExchange.Redis;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(swagg =>
{
    swagg.AddSecurityDefinition("basic", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        In = ParameterLocation.Header,
        Scheme = "basic",
        Type = SecuritySchemeType.Http,
        Description = "Basic Auth"
    });

    swagg.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "basic"
                }
            },
            new string[] {}
        }
    });
});

builder.Services.AddAuthentication()
    .AddScheme<CookieAuthenticationOptions, VisitorAuthHandler>("visitor", o=> { })
    .AddCookie("local")
    .AddCookie("external")
    .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>
            ("basic-auth", o => { })
    .AddOAuth("external-auth", o=>
    {
        o.SignInScheme = "external";

        o.ClientId = "id";
        o.ClientSecret = "secret";

        o.AuthorizationEndpoint = "https://oauth.mocklab.io/oauth/authorize";
        o.TokenEndpoint = "https://oauth.mocklab.io/oauth/token";
        o.UserInformationEndpoint = "https://oauth.mocklab.io/userinfo";

        o.CallbackPath = "/call-back-auth";

        o.Scope.Add("profile");
        o.SaveTokens = true;

    });

builder.Services.AddAuthorization(b =>
{
    b.AddPolicy("customer", p =>
    {
        p.AddAuthenticationSchemes("local", "visitor")
        .RequireAuthenticatedUser();
    });
    b.AddPolicy("user", p =>
    {
        p.AddAuthenticationSchemes("local")
        .RequireAuthenticatedUser();
    });
    b.AddPolicy("basic", p =>
    {
        p.AddAuthenticationSchemes("basic-auth")
        .RequireAuthenticatedUser();
    });
});

var redisMuxer = ConnectionMultiplexer.Connect("localhost:6379,abortConnect=false,password=password");
//builder.Services.AddSingleton<IConnectionMultiplexer>(redisMuxer);

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapGet("/redis/ping", async (HttpContext ctx) =>
{
    if (!redisMuxer.IsConnected)
        return Results.BadRequest("Database not found");

    var dataBase = redisMuxer.GetDatabase();
    var pong = await dataBase.PingAsync();

    return Results.Ok($"Database is ready\n Ping:{pong.TotalMilliseconds}ms");
});

app.MapPost("/redis/create", async (string key, string value) =>
{
    if (!redisMuxer.IsConnected)
        return Results.BadRequest("Database not found");

    var dataBase = redisMuxer.GetDatabase();
    //var serialized = JsonConvert.SerializeObject(value);
    await dataBase.StringSetAsync(key, value);
    return Results.Ok("added");
});

app.MapGet("/redis/read", async (string key) =>
{
    if (!redisMuxer.IsConnected)
        return Results.BadRequest("Database not found");

    var dataBase = redisMuxer.GetDatabase();
    string value =  await dataBase.StringGetAsync(key);
    //var value = JsonConvert.DeserializeObject<someObject>(rawValue);
    return Results.Ok(value);
});

var BookStore = new Books();

app.MapGet("/", async (HttpContext ctx) =>
{ 
    return Results.Ok();
}).RequireAuthorization("customer");

app.MapPost("/book", (Book book) =>
{
    BookStore.Add(book);
    return Results.Ok();
});

app.MapGet("/book/{id}", ([FromRoute] int id) =>
{
    var book = BookStore.Get(id);
    var result = book is null ? Results.NotFound() : Results.Ok(book);
    return result;
});

app.MapGet("/book", () =>
{
    var books = BookStore.Get();
    var result = books.Count == 0 ? Results.NotFound() : Results.Ok(books);
    return result;
}).RequireAuthorization("customer");

app.MapPut("/book", (Book book) =>
{
    BookStore.Update(book);
    return Results.Ok();
});

app.MapDelete("/book", (int id) =>
{
    BookStore.Delete(id);
    return Results.Ok();
});

app.MapGet("/login", async (HttpContext ctx) =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("user", "anonymous"));
    var identity = new ClaimsIdentity(claims, "local");
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync("local", user);
    return Results.Ok();
});

app.MapGet("/basicauth", async (HttpContext ctx) =>
{
    return Results.Ok();
}).RequireAuthorization("basic");

app.MapGet("/login-external", async (HttpContext ctx) => {

    await ctx.ChallengeAsync("external-auth", new AuthenticationProperties(){RedirectUri = "/swagger/index.html" });

}).RequireAuthorization("user");



app.Run();


public class VisitorAuthHandler : CookieAuthenticationHandler
{
    public VisitorAuthHandler(
        IOptionsMonitor<CookieAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock)
        : base (options, logger, encoder, clock) {}

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = await base.HandleAuthenticateAsync();
        if (result.Succeeded)
        {
            return result;
        }

        var claims = new List<Claim>();
        claims.Add(new Claim("user", "anonymous"));
        var identity = new ClaimsIdentity(claims, "visitor");
        var user = new ClaimsPrincipal(identity);

        await Context.SignInAsync("visitor", user);

        return AuthenticateResult.Success(new AuthenticationTicket(user, "visitor"));
    }
}

public class User
{
    public string Name { get; set; }
    public string Password { get; set; }
    public string Role { get; set; }
}


public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private User user;
    public BasicAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
            var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
            var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':');
            var username = credentials.First();
            var password = credentials.Last();

            user = new User()//HereSomeLoginLogic 
            {
                Name = username,
                Password = password,
                Role = "Admin"
            };
            if (user.Password != "123")
                throw new Exception();
        }
        catch (Exception ex)
        {
            return AuthenticateResult.Fail($"Auth fail:{ex.Message}");
        }

        var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.Role, user.Role)
            };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);

    }
}