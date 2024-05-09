using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

//generar el token con c#
string key = "keyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmF=";

//Agregamos el hecho de necesitar autorizacion
builder.Services.AddAuthorization();
builder.Services.AddAuthentication("Bearer").AddJwtBearer(opt =>
{
    //convertimos la cadena a una matriz de bites
    var signinKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
    var signinKeyCredentials = new
    SigningCredentials(signinKey, SecurityAlgorithms.HmacSha256Signature);

    opt.RequireHttpsMetadata= false;
    //para crear nuestro Token
    opt.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateAudience = false,
        ValidateIssuer = false,
        IssuerSigningKey = signinKey,
    };
});



var app = builder.Build();

app.MapGet("/", () => "Hello World!");

app.MapGet("/protected", (ClaimsPrincipal user) => user.Identity?.Name).
    RequireAuthorization(); //para esta ruta necesitaremos autenticacion es lo que indicamos con RequireAuthorization

//scope es el alcanze del usuario, solo accederan a este endpoint los usuarios con role myapi:drunken
app.MapGet("/protectedwithscope",
    (ClaimsPrincipal user) => user.Identity?.Name). // <= esto es lo que devuelve
    RequireAuthorization(p => p.RequireClaim("scope", "myapi:drunken"));


//EndPoint para autentificar
app.MapGet("/auth/{user}/{pass}", (string user, string pass) =>
{
    if (user == "pato" && pass == "donald")
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var byteKey = Encoding.UTF8.GetBytes(key);

        //describimos el cuerpo del token
        var tokenDescription = new SecurityTokenDescriptor
        {
            //agregamos los claims (piezas de informacion en el cuerpo del token)
            Subject = new System.Security.Claims.ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, user),
                new Claim("Scope", "myapi:drunken") //se define un nuevo alcance
            }),
            Expires = DateTime.UtcNow.AddMonths(1), //expira en un mes el token
            SigningCredentials = new SigningCredentials
            (new SymmetricSecurityKey(byteKey), SecurityAlgorithms.HmacSha256Signature)


        };
        var tokenForUser = tokenHandler.CreateToken(tokenDescription);
        return tokenHandler.WriteToken(tokenForUser);
    }
    else
    {
        return "Usuario invalido, verifique usuario y contraseña";
    }
});



app.Run();
