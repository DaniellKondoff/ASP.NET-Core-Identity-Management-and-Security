using Marvin.IDP.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Marvin.IDP
{
    public static class IdentityServerBuilderExtensions
    {
        public static IIdentityServerBuilder AddMarvinUserStore(this IIdentityServerBuilder builder)
        {
            builder.Services.AddTransient<IMarvinUserRepository, MarvinUserRepository>();
            builder.AddProfileService<MarvinUserProfileService>();

            return builder;
        }
    }
}
