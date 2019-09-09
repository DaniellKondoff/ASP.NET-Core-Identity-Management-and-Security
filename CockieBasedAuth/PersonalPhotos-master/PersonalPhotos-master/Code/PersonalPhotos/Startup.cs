using Core.Interfaces;
using Core.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PersonalPhotos.Filters;
using System;
using System.Reflection;

namespace PersonalPhotos
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
            services.AddMvc();
            services.AddSession();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddSingleton<IKeyGenerator, DefaultKeyGenerator>();

            services.AddScoped<ILogins, SqlServerLogins>();
            services.AddScoped<IPhotoMetaData, SqlPhotoMetaData>();
            services.AddScoped<IFileStorage, LocalFileStorage>();
            services.AddScoped<LoginAttribute>();

            var connectionString = Configuration.GetConnectionString("Default");
            var currentAsmName = Assembly.GetExecutingAssembly().GetName().Name;

            services.AddDbContext<IdentityDbContext>(opt =>
            {
                opt.UseSqlServer(connectionString, 
                    obj => obj.MigrationsAssembly(currentAsmName));
            });

            services.AddIdentity<IdentityUser, IdentityRole>(opt =>
            {
                opt.Password.RequireDigit = false;
                opt.Password.RequiredLength = 3;
                opt.Password.RequiredUniqueChars = 0;
                opt.Password.RequireLowercase = false;
                opt.Password.RequireUppercase = false;
                opt.Password.RequireNonAlphanumeric = false;

                opt.User.RequireUniqueEmail = true;

                opt.SignIn.RequireConfirmedEmail = false;

                opt.Lockout.AllowedForNewUsers = false;
                opt.Lockout.DefaultLockoutTimeSpan = new TimeSpan(0, 15, 0);
                opt.Lockout.MaxFailedAccessAttempts = 3;
            })
                .AddEntityFrameworkStores<IdentityDbContext>()
                .AddDefaultTokenProviders();

            services.ConfigureApplicationCookie(opt =>
            {
                opt.LoginPath = "/Logins/Index";
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseBrowserLink();
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();
            app.UseSession();
            app.UseAuthentication();
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    "default",
                    "{controller=Photos}/{action=Display}");
            });
        }
    }
}