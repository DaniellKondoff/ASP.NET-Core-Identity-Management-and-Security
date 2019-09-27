using Microsoft.AspNetCore.Authorization;

namespace ImageGallery.Client.Authorization
{
    public class MustOwnImageRequirment : IAuthorizationRequirement
    {
        public MustOwnImageRequirment()
        {

        }
    }
}
