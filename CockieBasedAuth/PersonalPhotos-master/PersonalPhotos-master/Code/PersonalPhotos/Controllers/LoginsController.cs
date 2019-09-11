﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PersonalPhotos.Interfaces;
using PersonalPhotos.Models;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace PersonalPhotos.Controllers
{
    public class LoginsController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmail _emailService;

        public LoginsController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IEmail emailService,
            RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _emailService = emailService;
        }

        public IActionResult Index(string returnUrl = null)
        {
            var model = new LoginViewModel { ReturnUrl = returnUrl };
            return View("Login", model);
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Invalid login detils");
                return View("Login", model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null || !user.EmailConfirmed)
            {
                ModelState.AddModelError("", "User not found or Email is not Confirmed");
                return View("Login", model);
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);
            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Username and/or Password is incorrect");
                return View();
            }

            var claims = new List<Claim>();
            claims.Add(new Claim("Over18Claim", "True"));

            var claimIdentity = new ClaimsIdentity(claims);

            User.AddIdentity(claimIdentity);

            if (!string.IsNullOrEmpty(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }
            else
            {
                return RedirectToAction("Display", "Photos");
            }
        }

        public IActionResult Create()
        {
            return View("Create");
        }

        [HttpPost]
        public async Task<IActionResult> Create(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Invalid user details");
                return View(model);
            }

            if (!(await _roleManager.RoleExistsAsync("Editor")))
            {
                await _roleManager.CreateAsync(new IdentityRole("Editor"));
            }

            var user = new IdentityUser
            {
                UserName = model.Email,
                Email = model.Email,
            };


            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, $"{error.Code} : {error.Description}");
                }

                return View(model);
            }

            //if (!User.IsInRole("Editor"))
            //{
            //    await _userManager.AddToRoleAsync(user, "Editor");
            //}

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var url = Url.Action("Confirmation", "Logins", new { id = user.Id, @token = token });

            var emailBody = $"Please Confirm your email by clicking on the link below <br/><br/> {url}";

            await _emailService.Send(model.Email, emailBody);

            return RedirectToAction("Index", "Logins");
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction("Index", "Logins");
        }

        [HttpGet]
        public async Task<IActionResult> Confirmation(string id, string token)
        {
            var user = await _userManager.FindByIdAsync(id);
            var confirm = await _userManager.ConfirmEmailAsync(user, token);

            if (confirm.Succeeded)
            {
                return RedirectToAction("Index");
            }

            ViewData["Error"] = "Error with validating the email address";

            return View();
        }

        public async Task<IActionResult> ResetPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.EmailAddress);

            if (user != null && user.EmailConfirmed)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var url = Url.Action("ChangePassword", "Logins", new { userId = user.Id, token }, protocol:HttpContext.Request.Scheme);
                var emailBody = $"Click on the link for resetting your password <br /> {url}";

                await _emailService.Send(model.EmailAddress, emailBody);
            }

            return RedirectToAction("Index");
        }

        public async Task<IActionResult> ChangePassword(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
            {
                return View();
            }

            var model = new ChangePasswordViewModel();
            ViewData["EmailAddress"] = user.Email;
            TempData["EmailAddress"] = user.Email;
            TempData["PasswordToken"] = token;

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Error in resseting a password");
                return View(model);
            }
            string emailAddress = TempData["EmailAddress"].ToString();
            string token = TempData["PasswordToken"].ToString();
            var user = await _userManager.FindByEmailAsync(emailAddress);
            var resetPasswordResult = await _userManager.ResetPasswordAsync(user, token, model.Password);


            return RedirectToAction("Index");
        }
    }
}