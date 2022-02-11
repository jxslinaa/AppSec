using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using AppSec.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AppSec.Controllers
{
    public class DashboardController : Controller
    {
        public readonly AppSecContext _contxt;
        public DashboardController(AppSecContext context)
        {
            _contxt = context;
        }


        //Intializing the session used to session if regeneration conflict, we enabeld the guest checkout
      /*  private void initSession()
        {
            HttpContext.Session.SetInt32("userId", 0);
            HttpContext.Session.SetString("userName", string.Empty);
            HttpContext.Session.SetString("userType", "Guest");
            //userName
        }*/
        [Authorize(Roles = "Admin")]
        public IActionResult index()
        {
            //SESSION CHECK
            int? userId = (HttpContext.Session.GetInt32("userId"));
            string CartSessionId = HttpContext.Session.Id;

           // if (userId == null || userId == 0)
            //    this.initSession();
            ViewData["userId"] = (userId == null || userId == 0) ? 0 : userId;


            return View();

        }
        [Route("error/404")]
        public IActionResult page404() {
            return View("~/Views/Shared/NotFound.cshtml");
        }
        [Route("error/403")]
        public IActionResult pageErr()
        {
            return View("~/Views/Shared/403Page.cshtml");
        }


        //step checkout - Cart summary page
        //if the session is empty then redirect to signup / login page 

        [Authorize(Roles = "Admin")]
        //CURRENT USER PPROFILE ie,LOGGED USER details
        public IActionResult MyProfile()
        {
            ViewData["errorMsg"] = "";
            try
            {

                int? userId = (int)(HttpContext.Session.GetInt32("userId"));
                Users customer = _contxt.Users.Where(x => x.UserId == userId).SingleOrDefault();

                string imageBase64Data = Convert.ToBase64String(customer.ProfilePhoto);
                string imageDataURL = string.Format("data:image/*;base64,{0}",imageBase64Data);
                ViewBag.ImageDataUrl = imageDataURL;
                customer.CardNumber = Helper.Decrypt(customer.CardNumber, "moresecu", "privatky");
                ViewData["password_change"] = "";
                if( customer.PasswordExpiryUtc > DateTime.Now )
                    ViewData["password_change"] = "You cant change your password untill "+customer.PasswordExpiryUtc;
                ViewData["Msg"] = "Your current password has expired. You must change your password in order to secure your account.";
                return View(customer);
            }
            catch (Exception e)
            {

                return NotFound();
            }
        }

        //user details update
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult MyProfile(Users updateCustomer)
        {
            ViewData["errorMsg"] = "";
            try
            {
                int userId = Int32.Parse(HttpContext.Session.GetString("userId"));
                Users customer = _contxt.Users.Where(x => x.UserId == userId).SingleOrDefault();
                customer.FirstName = updateCustomer.FirstName;
                customer.LastName = updateCustomer.LastName;
                customer.MobileNumber = updateCustomer.MobileNumber;
                customer.Email = updateCustomer.Email;
                _contxt.Users.Update(customer);
                _contxt.SaveChanges();
                ViewData["errorMsg"] = "Your profile updated successfully";
                return View(customer);
            }
            catch (Exception e)
            {
                ViewData["errorMsg"] = "";
                return NotFound();
            }
        }


    }
}
