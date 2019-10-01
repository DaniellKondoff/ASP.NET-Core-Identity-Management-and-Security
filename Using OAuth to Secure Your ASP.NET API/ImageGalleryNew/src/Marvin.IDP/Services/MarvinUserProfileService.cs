using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Marvin.IDP.Services
{
    public class MarvinUserProfileService : IProfileService
    {
        private readonly IMarvinUserRepository marvinUserRepository;
        public MarvinUserProfileService(IMarvinUserRepository marvinUserRepository)
        {
            this.marvinUserRepository = marvinUserRepository;
        }

        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var subjectId = context.Subject.GetSubjectId();
            var claimsForUser = marvinUserRepository.GetUserClaimsBySubjectId(subjectId);

            context.IssuedClaims = claimsForUser
                .Select(c => new Claim(c.ClaimType, c.ClaimValue))
                .ToList();

            return Task.FromResult(0);
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            var subjectId = context.Subject.GetSubjectId();
            context.IsActive = marvinUserRepository.IsUserActive(subjectId);

            return Task.FromResult(0);
        }
    }
}
