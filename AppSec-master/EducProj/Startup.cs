using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using AppSec.Models;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace AppSec
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        public IConfiguration Configuration { get; }
        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var sessionExpireTimeSPan = 300;
            AppSecContext.connString = Configuration.GetConnectionString("AppSecContext");
          //  services.Configure<CookiePolicyOptions>(options =>
          //  {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
             //   options.CheckConsentNeeded = context => true;
            //    options.MinimumSameSitePolicy = SameSiteMode.None;
           // });
            services.AddDistributedMemoryCache();//by me
          
            //created by me
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromSeconds(sessionExpireTimeSPan);
                options.Cookie.Name = ".AppSec.sessions";
                options.Cookie.IsEssential = true;
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
                options.Cookie.SameSite = SameSiteMode.None;

            });
           
            services.AddDbContext<AppSecContext>(options =>
                    options.UseSqlServer(Configuration.GetConnectionString("AppSecContext")));
            var connStr = Configuration.GetConnectionString("AppSecContext");

             services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(x=> { 
                 x.LoginPath = "/User/Login";
              //   x.CookieHttpOnly = true;
              //   x.CookiePath = "/";
              //   x.CookieSecure=CookieSecurePolicy.Always;
                 x.Cookie.SameSite = SameSiteMode.None;
                 x.ExpireTimeSpan = TimeSpan.FromSeconds(sessionExpireTimeSPan);
             });//FOr security 


            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Dashboard/Index");
                app.UseHsts();
            }
            app.UseSession();//created by me
            app.UseMvc();//created by me
            app.UseStaticFiles();
            app.UseCookiePolicy();
            app.UseAuthentication();//FOr security 
            app.UseStatusCodePagesWithReExecute("/error/{0}");
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=User}/{action=Login}");
               

            });
        



        }
    }
}
//this is the final susbmission file