using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace WebApiJwtExample
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            string mykeyname = "the secret that needs to be at least 16 characeters long for HmacSha256";

            // Add cors
            services.AddCors();

            services.AddAuthorization(auth =>
            {
                auth.AddPolicy(Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme, new AuthorizationPolicyBuilder()
                    .AddAuthenticationSchemes(Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme‌​)
                    .RequireAuthenticatedUser()
                    .Build());
            });

            services.AddAuthentication(Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme)
                            .AddJwtBearer(options =>
                            {
                                options.RequireHttpsMetadata = false;
                                options.SaveToken = true;
                                options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                                {
                                    //ValidIssuer = "dp_portal_api",
                                    //ValidAudiences = new[] { "dp_portal_spa" },
                                    ValidateAudience = false,
                                    ValidateIssuer = false,
                                    ValidateIssuerSigningKey = true,
                                    IssuerSigningKeys = new List<SecurityKey> {
                                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mykeyname) )},
                                    ValidateLifetime = true, //validate the expiration and not before values in the token
                                    ClockSkew = TimeSpan.FromMinutes(5) //5 minute tolerance for the expiration date
                                };
                            });

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            //Configure Cors
            app.UseCors(builder => builder
                .AllowAnyOrigin()
                //.WithOrigins("http://localhost:4200")
                .AllowAnyHeader()
                .AllowAnyMethod());

            app.UseAuthentication();

            app.UseMvcWithDefaultRoute();

            app.Run(async (context) =>
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsync("Page not found");
            });
        }
    }
}
