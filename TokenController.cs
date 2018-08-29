using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace WebApiJwtExample
{
    [Route("/api/token")]
    public class TokenController : Controller
    {
        string mykeyname = "the secret that needs to be at least 16 characeters long for HmacSha256";

        [HttpPost]
        public JsonWebToken Create([FromBody]TokenModel obj)
        {

            User user = obj.grant_type == "refresh_token" ? GetUserByToken(obj.refresh_token) : GetUserByCredentials(obj.username, obj.password);

            if (user == null)
                throw new UnauthorizedAccessException("No!");

            int ageInMinutes = 20;  // However long you want...

            DateTime expiry = DateTime.UtcNow.AddMinutes(ageInMinutes);

            var token = new JsonWebToken
            {
                access_token = GenerateToken(user, expiry),
                expires_in = ageInMinutes * 60
            };

            if (obj.grant_type != "refresh_token")
                token.refresh_token = GenerateRefreshToken(user);
            return token;
        }

        private User GetUserByToken(string refreshToken)
        {
            // TODO: Check token against your database.
            string[] Roles = { "Administrator" };
            if (refreshToken == "test")
                return new User
                {
                    UserName = "test",
                    permission = "contents",
                    Roles = Roles
                };

            return null;
        }

        private User GetUserByCredentials(string username, string password)
        {
            string[] Roles = { "Administrator" };
            // TODO: Check username/password against your database.
            if (username == "test" && password == "dev123")
                return new User
                {
                    UserName = "test",
                    permission = "contents",
                    Roles = Roles
                };

            return null;
        }

        private string GenerateRefreshToken(User user)
        {
            // TODO: Create and persist a refresh token.
            return "test";
        }
        
        public string GenerateToken(User user, DateTime expiry)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            ClaimsIdentity identity = new ClaimsIdentity(new GenericIdentity(user.UserName, "jwt"));

            RsaSecurityKey _key;
            string _algorithm = SecurityAlgorithms.RsaSha256Signature;
            string _issuer = "dp_portal_api";
            string _audience = "dp_portal_spa";
            string keyName = mykeyname;

            var parameters = new CspParameters { KeyContainerName = keyName };
            var provider = new RSACryptoServiceProvider(2048, parameters);
            _key = new RsaSecurityKey(provider);

            SecurityToken token = tokenHandler.CreateJwtSecurityToken(new SecurityTokenDescriptor
            {
                Audience = _audience,
                Issuer = _issuer,
                SigningCredentials = new SigningCredentials(_key, _algorithm),
                Expires = expiry.ToUniversalTime(),
                Subject = identity
            });
            
            return tokenHandler.WriteToken(token);
        }
    }

    public class User
    {
        public string UserName { get; set; }
        public string[] Roles { get; set; }
        public string permission { get; set; }
    }

    public class JsonWebToken
    {
        public string access_token { get; set; }

        public string token_type { get; set; } = "bearer";

        public int expires_in { get; set; }

        public string refresh_token { get; set; }
    }


    public class TokenModel
    {
        public string username { get; set; }

        public string password { get; set; }

        public string client_id { get; set; }

        public string grant_type { get; set; }

        public string scope { get; set; }

        public string refresh_token { get; set; }
    }
}