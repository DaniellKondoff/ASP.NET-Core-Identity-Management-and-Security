using IdentityServer4.Services;
using Marvin.IDP.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace Marvin.IDP.Controllers.UserRegistration
{
    public class UserRegistrationController : Controller
    {
        private readonly IMarvinUserRepository marvinUserRepository;
        private readonly IIdentityServerInteractionService interactionService;

        public UserRegistrationController(IMarvinUserRepository marvinUserRepository, IIdentityServerInteractionService interactionService)
        {
            this.marvinUserRepository = marvinUserRepository;
            this.interactionService = interactionService;
        }

        [HttpGet]
        public IActionResult RegisterUser(string returnUrl)
        {
            var vm = new RegisterUserViewModel()
            {
                ReturnUrl = returnUrl
            };

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegisterUser(RegisterUserViewModel model)
        {
            if (ModelState.IsValid)
            {
                // create user + claims
                var userToCreate = new Entities.User();
                userToCreate.Password = model.Password;
                userToCreate.Username = model.Username;
                userToCreate.IsActive = true;
                userToCreate.Claims.Add(new Entities.UserClaim("country", model.Country));
                userToCreate.Claims.Add(new Entities.UserClaim("address", model.Address));
                userToCreate.Claims.Add(new Entities.UserClaim("given_name", model.Firstname));
                userToCreate.Claims.Add(new Entities.UserClaim("family_name", model.Lastname));
                userToCreate.Claims.Add(new Entities.UserClaim("email", model.Email));
                userToCreate.Claims.Add(new Entities.UserClaim("subscriptionlevel", "FreeUser"));

                // add it through the repository
                marvinUserRepository.AddUser(userToCreate);

                if (!marvinUserRepository.Save())
                {
                    throw new Exception($"Creating a user failed.");
                }

                // log the user in
                //await HttpContext.Authentication.SignInAsync(userToCreate.SubjectId, userToCreate.Username);
                await AuthenticationHttpContextExtensions.SignInAsync(HttpContext, User);

                // continue with the flow     
                if (interactionService.IsValidReturnUrl(model.ReturnUrl) || Url.IsLocalUrl(model.ReturnUrl))
                {
                    return Redirect(model.ReturnUrl);
                }

                return Redirect("~/");
            }

            // ModelState invalid, return the view with the passed-in model
            // so changes can be made
            return View(model);
        }
    }
}
