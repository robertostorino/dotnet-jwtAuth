using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using renaper.simulator.model;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
//using Microsoft.Extensions.Primitives;

namespace renaper.simulator.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly string secretkey;

        // Obtengo la clave secreta que está guardada en appsettings.
        public AuthController(IConfiguration conf)
        {
            secretkey = conf.GetSection("settings").GetSection("secretkey").ToString();
        }

        public class GlobalToken
        {
            public static string TOKEN_GLOBAL { get; set; }
        }

        //> NUEVO
        [HttpPost]
        [Route("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            if (request.Username == "usuario" && request.Password == "usuario")
            {
                var keyBytes = Encoding.ASCII.GetBytes(secretkey);
                var claims = new ClaimsIdentity();

                // solicitud de permisos
                claims.AddClaim(new Claim(ClaimTypes.NameIdentifier, request.Username));

                // configuración del token
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = claims,
                    Expires = DateTime.UtcNow.AddMinutes(120), //expira en 2 horas
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256Signature),
                };

                // creo el token
                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenConfig = tokenHandler.CreateToken(tokenDescriptor);

                // obtengo el token creado
                string tokencreado = tokenHandler.WriteToken(tokenConfig);

                GlobalToken.TOKEN_GLOBAL = tokencreado; // para control de pruebas. En producción lo debo corregir.

                

                //return StatusCode(StatusCodes.Status200OK, new { token = tokencreado});

                var response = new
                {
                    codigo_http = 200,
                    mensaje_http = "OK",
                    data = new
                    {
                        codigo = 0,
                        mensaje = "TOKEN GENERADO",
                        token = tokencreado
                    }
                };

                //return StatusCode(StatusCodes.Status200OK, response);
                return Ok(response);

            }
            else
            {
                return StatusCode(StatusCodes.Status401Unauthorized, new { token = "" });
            }
        }

        //< NUEVO

        //public class LoginRequest
        //{
        //    public string Username { get; set; }
        //    public string Password { get; set; }
        //}

        [HttpPut]
        [Route("crearCliente")]
        [Authorize] // Requiere autenticación para acceder a esta acción
        public IActionResult CrearCliente([FromBody] ClienteRequest request)
        {
            // lógica para crear un cliente aquí

            var tokenFromRequest = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var tokenAlmacenado = GlobalToken.TOKEN_GLOBAL;
            //var tokenAlmacenado = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzdWFyaW8iLCJwYXNzd29yZCI6InVzdWFyaW8ifQ.pDqctHZN5Z-3ejzbAZVnr8cixLBz7JutG6P-C83fw18";

            // Compara ambos tokens

            if (tokenFromRequest == tokenAlmacenado)
            {
                var response = new
                {
                    codigo = 201,
                    mensaje = "CLIENTE CREADO",
                    id_cliente = 729252,
                    fecha_alta = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
                };
                return Ok(response);

            } else
            {
                var errorResponse = new
                {
                    codigo = 401,
                    mensaje = "ACCESO DENEGADO"
                };
                return Unauthorized(errorResponse);
            }
        }

        //public class ClienteRequest
        //{
        //    public Int16 dni { get; set; }
        //    public string sexo { get; set; }
        //}
    }
}
