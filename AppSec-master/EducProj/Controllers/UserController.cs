using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AppSec.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using static System.Net.Mime.MediaTypeNames;
//REFERECNCE: https://www.c-sharpcorner.com/article/authentication-and-authorization-in-asp-net-core-mvc-using-cookie/
//https://docs.microsoft.com/en-us/aspnet/mvc/overview/security/create-an-aspnet-mvc-5-web-app-with-email-confirmation-and-password-reset
//RECAPATCHA
//https://www.c-sharpcorner.com/blogs/google-recaptcha-in-asp-net-mvc
namespace AppSec.Controllers
{
    public class UserController : Controller
    {
        public readonly AppSecContext _contxt;
        public UserController(AppSecContext context)
        {
            _contxt = context;
        }

        //check processing viewing page 
        public IActionResult checkout()
        {
            int? userId = HttpContext.Session.GetInt32("userId");
            if (userId == null || userId == 0)
                return RedirectToAction("Signup", "User");

            return View();
        }


        [AllowAnonymous]
        public IActionResult login()
        {
            int? userId = HttpContext.Session.GetInt32("userId");
            if (userId != null && userId != 0)
                return RedirectToAction("MyProfile", "Dashboard");
            ViewData["errorMsg"] = "";
            return View();
        }
        [AllowAnonymous]
        public async Task<JsonResult> VerifyCaptcha(string token)
        {
            var dictionary = new Dictionary<string, string>
                    {
                        { "secret", "6LeH9WceAAAAAEDFnEUu_z7emFdP3PLouPOsd27Q"},
                        { "response", token }
                    };

            var postContent = new FormUrlEncodedContent(dictionary);

            HttpResponseMessage recaptchaResponse = null;
            string stringContent = "";
            // Call recaptcha api and validate the token
            using (var http = new HttpClient())
            {
                recaptchaResponse = await http.PostAsync("https://www.google.com/recaptcha/api/siteverify", postContent);
                stringContent = await recaptchaResponse.Content.ReadAsStringAsync();
                if (!recaptchaResponse.IsSuccessStatusCode)
                {
                    return Json(new { status = false, message = "Unable to verify recaptcha token", ErrorCode = "S03" });
                }

                if (string.IsNullOrEmpty(stringContent))
                {
                    return Json(new { status = false, message = "Invalid reCAPTCHA verification response", ErrorCode = "S04" });
                }
                var googleReCaptchaResponse = JsonConvert.DeserializeObject<RecaptchaResponse>(stringContent);

                if (!googleReCaptchaResponse.Success)
                {
                    var errors = string.Join(",", googleReCaptchaResponse.ErrorCodes);

                    return Json(new { status = false, message = errors, ErrorCode = "S05" });
                }

                if (!googleReCaptchaResponse.Action.Equals("registration", StringComparison.OrdinalIgnoreCase))
                {
                    // This is important just to verify that the exact action has been performed from the UI
                    return Json(new { status = false, message = "Invalid action", ErrorCode = "S06" });
                }

                // Captcha was success , let's check the score, in our case, for example, anything less than 0.5 is considered as a bot user which we would not allow ...
                // the passing score might be higher or lower according to the sensitivity of your action

                if (googleReCaptchaResponse.Score < 0.5)
                {
                    return Json(new { status = false, message = "This is a potential bot. Signup request rejected", ErrorCode = "S07" });
                }

                //TODO: Continue with doing the actual signup process, since now we know the request was done by potentially really human

                return Json(new { status = true });

            }

            return Json(new { status = false, message = "" });
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public JsonResult UpdatePassword(string CurrentPassword, string NewPassword, string ConfirmPassword)
        {
            try
            {

                int? userId = HttpContext.Session.GetInt32("userId");

                NewPassword = NewPassword.Trim();
                ConfirmPassword = ConfirmPassword.Trim();
                if (string.IsNullOrEmpty(CurrentPassword) || string.IsNullOrEmpty(NewPassword) || string.IsNullOrEmpty(ConfirmPassword))
                {
                    return Json(new { status = false, message = "Invalid input" });
                }
                else if (ConfirmPassword != NewPassword)
                {
                    return Json(new { status = false, message = "Password not equal" });
                }
                else if (ConfirmPassword.Length < 12)
                {
                    return Json(new { status = false, message = "Password must contains 12 character length" });

                }
                else if (!String.IsNullOrEmpty(ConfirmPassword))
                {

                    int upper = 0, lower = 0, number = 0, special = 0, whitespace = 0;
                    foreach (char c in ConfirmPassword)
                    {
                        if (Char.IsUpper(c))
                            upper++;
                        if (Char.IsLower(c))
                            lower++;
                        if (Char.IsDigit(c))
                            number++;
                        if (Char.IsSymbol(c))
                            special++;
                        if (Char.IsWhiteSpace(c))
                            whitespace++;
                    }
                    if (upper < 2 || lower < 2 || number < 2 || special < 1 || whitespace != 0)
                        return Json(new { status = false, message = "Strong password required{ Must contains 2 upper and  2 lower case and  2 number and atleast one special character}" });

                    int loggedUserId = Int32.Parse(userId.ToString());

                    Users loggedCustomer = _contxt.Users.Where(x => x.UserId == userId).FirstOrDefault();
                    string CurrentPasswordEnc = Helper.EncodePassword(CurrentPassword.Trim(), loggedCustomer.PasswordSalt.TrimStart().TrimEnd());

                    string userPassword = Helper.EncodePassword(CurrentPassword.Trim(), loggedCustomer.PasswordSalt.TrimStart().TrimEnd());


                    string newPasswordEnc = Helper.EncodePassword(NewPassword.Trim(), loggedCustomer.PasswordSalt.TrimStart().TrimEnd());
                    if (CurrentPasswordEnc.Equals(loggedCustomer.Password))
                    {
                        //check the previous password
                        IList<PasswordHistory> pwd_histories = _contxt.PasswordHistory.Where(x => x.UserId == userId).OrderByDescending(x => x.CreatedDate).Take(2).ToList();
                        foreach (PasswordHistory pwdHistory in pwd_histories)
                        {
                            string oldPassword = pwdHistory.Password.Trim();//, pwdHistory.PasswordSalt.TrimStart().TrimEnd());
                            if (newPasswordEnc.Equals(oldPassword))
                            {
                                return Json(new { status = false, message = "You can't use your recent password" });
                            }
                        }
                        DateTime newPExpiry = (DateTime)(loggedCustomer.PasswordExpiryUtc?.AddDays(1));
                        //update password
                        loggedCustomer.Password = newPasswordEnc;
                        loggedCustomer.PasswordExpiryUtc = newPExpiry;
                        _contxt.Users.Update(loggedCustomer);
                        _contxt.SaveChanges();

                        PasswordHistory newHistry = new PasswordHistory();
                        newHistry.UserId = loggedUserId;
                        newHistry.Password = newPasswordEnc;
                        newHistry.PasswordSalt = loggedCustomer.PasswordSalt;
                        newHistry.CreatedDate = DateTime.Now;
                        _contxt.PasswordHistory.Add(newHistry);
                        _contxt.SaveChanges();

                        this.logout();
                        return Json(new { status = true, message = "Password changed successfully, Please login to continue" });
                    }
                    else
                    {
                        return Json(new { status = false, message = "Invalid current password" });
                    }
                }
            }
            catch (Exception e)
            {
                return Json(new { status = false, message = "" });
            }
            return Json(new { status = false, message = "Error try again later" });
        }
        //login processing - steps mentioned inside
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult login(Users customer)
        {
            ViewData["errorMsg"] = "";
            string errMsg = "-NA-";
            if (customer != null)
            {
                //fetching user details from email - logged username
                Users loggedCustomer = _contxt.Users.Where(x => x.Email.Equals(customer.Email)).FirstOrDefault();
                //if the user details are empty then we raise error
                if (loggedCustomer == null)
                {
                    ViewData["errorMsg"] = "Invalid user details";
                    return View();
                }
                else
                {
                    string userPassword = Helper.EncodePassword(customer.Password, loggedCustomer.PasswordSalt.TrimStart().TrimEnd());

                    
                    if (userPassword.Equals(loggedCustomer.Password))
                    {
                        if (loggedCustomer.LockOutEndDateUtc != null && loggedCustomer.LockOutEndDateUtc > DateTime.Now)
                        {
                            ViewData["errorMsg"] = string.Format("Your account is locked untill {0}, Contact support for further assistance", loggedCustomer.LockOutEndDateUtc);
                            return View();
                        }


                        if (loggedCustomer.EmailValidated == 0)
                        {
                            ViewData["errorMsg"] = "Your account is not activated, Please confirm your email";
                            return View();
                        }
                        
                        if (loggedCustomer.isActive == 1 && loggedCustomer.EmailValidated == 1)
                        {
                            ViewData["errorMsg"] = "";
                            //step 4
                            HttpContext.Session.SetString("userName", loggedCustomer.FirstName);
                            HttpContext.Session.SetInt32("userId", loggedCustomer.UserId);
                            HttpContext.Session.SetString("userType", "");
                            ClaimsIdentity identity = null;
                            var sessId = HttpContext.Session.Id;
                            loggedCustomer.FailedLogins = 0;
                            loggedCustomer.LastLogin = DateTime.Now;

                            loggedCustomer.LockOutEndDateUtc = null;
                            _contxt.Users.Update(loggedCustomer);
                            _contxt.SaveChanges();
                            var usId = HttpContext.Session.GetInt32("userId");
                            //step 5
                            //Create the identity for the user  
                            identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, customer.Email), new Claim(ClaimTypes.Role, "Admin") }, CookieAuthenticationDefaults.AuthenticationScheme);

                            var principal = new ClaimsPrincipal(identity);
                            var login = HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                            return RedirectToAction("MyProfile", "Dashboard");
                        }
                    }
                    else
                    {
                        errMsg = "Invalid Login";
                        ViewData["errorMsg"] = errMsg;
                        loggedCustomer.FailedLogins = loggedCustomer.FailedLogins + 1;
                        if (loggedCustomer.FailedLogins >= 3)
                        {
                            ViewData["errorMsg"] = "Account locked on expiry date contact support";

                            loggedCustomer.LockOutEndDateUtc = DateTime.Now.AddDays(3);
                        }
                        _contxt.Users.Update(loggedCustomer);
                        _contxt.SaveChanges();
                        return View();
                    }
                }
                ViewData["errorMsg"] = errMsg;

                return View();
            }
            return View(); 
        }



        //Steps: 1. Check the current request already having session,
        //2.if not show the page,
        //3. else stay in login page
        public IActionResult Signup()
        {

            int? userId = HttpContext.Session.GetInt32("userId");
            if (userId != null && userId != 0)
                return RedirectToAction("MyProfile", "Dashboard");

            ViewData["errorMsg"] = "";
            Users customer = new Users();
            return View(customer);
        }
        public ActionResult activateAccount(string authTOken, int userId)
        {
            ViewData["status"] = string.Empty;
            if ((!string.IsNullOrEmpty(authTOken)) && userId != 0)
            {
                Users userdetails = _contxt.Users.Where(x => x.AuthToken.Equals(authTOken) && x.UserId == userId).SingleOrDefault();
                if (userdetails != null)
                {
                    if (userdetails.EmailValidated == 0)
                    {
                        userdetails.EmailValidated = 1;
                        userdetails.isActive = 1;
                        _contxt.Users.Update(userdetails);
                        _contxt.SaveChanges();
                        ViewData["status"] = "Activated Successfully";
                        return View();
                    }
                    else
                    {
                        ViewData["status"] = "Already Activated, Login to your account with credentials";
                        return View();
                    }
                }
                else
                {
                    return View("~/views/shared/NotFound.cshtml");
                }
            }
            return View("~/views/shared/NotFound.cshtml");
        }
        //step1: Create encryption key.
        //step2: validate all fields, Check for duplicate email entry, Check the password length is 6 letters
        //step3: Hash the password with created encryption key
        //step4: save all entries in database.


        //Password strength Approach
        /*
         * Scan string str from 0 to length-1.
        check one character at a time on the basis of ASCII values 
        if(str[i] >= 65 and str[i] <=90), then it is uppercase letter, 

        if(str[i] >= 97 and str[i] <=122), then it is lowercase letter, 

        if(str[i] >= 48 and str[i] <=57), then it is number, 

        else it is a special character
        Print all the counters.
        */

        [HttpPost]
        public JsonResult Signup(Users customer)
        {
            string errorMsg = string.Empty;
            string saltString = "Abcfjlk12!@#$";// Helper.GeneratePassword(10);

            if (customer != null)
            {

                string publickey = "moresecu";//8key length
                string secretkey = "privatky";//8key length

                //https://www.c-sharpcorner.com/article/how-to-encrypt-and-decrypt-in-c-sharp-using-simple-aes-keys/


                if (String.IsNullOrEmpty(customer.FirstName) || String.IsNullOrEmpty(customer.LastName) || String.IsNullOrEmpty(customer.Email) || String.IsNullOrEmpty(customer.Password) || String.IsNullOrEmpty(customer.c_password) || String.IsNullOrEmpty(customer.Email) || String.IsNullOrEmpty(customer.CardNumber) || String.IsNullOrEmpty(customer.CardExpiryDate) || String.IsNullOrEmpty(customer.CardCVV) || String.IsNullOrEmpty(customer.NameOnCard) || customer.DOB == null || customer.Fileinps == null)
                {
                    errorMsg = "Invalid input";
                }
                else if (customer.Password != customer.c_password)
                {
                    errorMsg = "Confirm passwordd";
                }
                else if (customer.CardNumber.Length < 12 || customer.CardCVV.Length < 3)
                {
                    errorMsg = "Invalid card number";
                }
                else if (customer.MobileNumber.Length < 10)
                {
                    errorMsg = "Invalid mobile number";
                }
                else if (_contxt.Users.Any(x => x.MobileNumber.Equals(customer.MobileNumber)))
                {
                    errorMsg = "Mobile number exists";
                }
                else if (_contxt.Users.Any(x => x.Email.Equals(customer.Email)))
                {
                    errorMsg = "Email already exists";
                }
                else if (customer.Password.Length < 12)
                {
                    errorMsg = "Password must contains 12 character length";
                }
                else if (!String.IsNullOrEmpty(customer.Email))
                {
                    var emailValidation = new EmailAddressAttribute();
                    if (!emailValidation.IsValid(customer.Email))
                    {
                        errorMsg = "Invalid email";
                    }
                }
                else if (!String.IsNullOrEmpty(customer.Password))
                {
                    /*
                     *  Scan string str from 0 to length-1.
                        check one character at a time on the basis of ASCII values 
                        if(str[i] >= 65 and str[i] <=90), then it is uppercase letter, 
                        if(str[i] >= 97 and str[i] <=122), then it is lowercase letter, 
                        if(str[i] >= 48 and str[i] <=57), then it is number, 
                           else it is a special character
                    */
                    int upper = 0, lower = 0, number = 0, special = 0, whitespace = 0;
                    foreach (char c in customer.Password)
                    {
                        if (Char.IsUpper(c))
                            upper++;
                        if (Char.IsLower(c))
                            lower++;
                        if (Char.IsDigit(c))
                            number++;
                        if (Char.IsSymbol(c))
                            special++;
                        if (Char.IsWhiteSpace(c))
                            whitespace++;
                    }
                    if (upper < 2 || lower < 2 || number < 2 || special < 1 || whitespace != 0)
                        errorMsg = "Strong password required{ Must contains 2 upper and  2 lower case and  2 number and atleast one special character}";
                }
                else if (customer.Fileinps != null)
                {
                    //FILE VALIDATIONS START
                    var contType = customer.Fileinps.ContentType;
                }

                if (String.IsNullOrEmpty(errorMsg))
                {
                    customer.CreatedDate = DateTime.Now;
                    customer.UpdatedDate = DateTime.Now;
                    customer.isActive = 0;
                    customer.EmailValidated = 0;
                    customer.PasswordSalt = saltString;
                    customer.LastLogin = null;
                    customer.TwoFactorEnabled = 1;
                    customer.AuthToken = Guid.NewGuid().ToString();
                    customer.LockOutEndDateUtc = null;
                    customer.DOB = DateTime.Parse(customer.DOB?.ToString("yyyy-MM-dd 16:52:29.627"));


                    // Create a new instance of the AesManaged
                    // class.  This generates a new key and initialization
                    // vector (IV).
                    // var encrt = Helper.Encrypt(customer.CardNumber, publickey, secretkey);
                    //var decryptedTxt = Helper.Decrypt(encrt, publickey, secretkey);
                    customer.CardNumber = Helper.Encrypt(customer.CardNumber, publickey, secretkey);


                    if (customer.Fileinps != null)
                    {
                        if (customer.Fileinps.Length > 0)
                        //Convert Image to byte and save to database
                        {

                            byte[] p1 = null;
                            using (var fs1 = customer.Fileinps.OpenReadStream())
                            using (var ms1 = new MemoryStream())
                            {
                                fs1.CopyTo(ms1);
                                p1 = ms1.ToArray();
                            }
                            customer.ProfilePhoto = p1;
                        }
                    }

                    try
                    {
/*                        customer.PasswordExpiryUtc = DateTime.Now.AddDays(15);//expiry date for password
*/
                        customer.Password = Helper.EncodePassword(customer.Password, saltString.TrimStart().TrimEnd());
                        customer.PasswordSalt = saltString.TrimStart().TrimEnd();
                        customer.PasswordExpiryUtc = DateTime.Now;
                        _contxt.Users.Add(customer);
                        _contxt.SaveChanges();

                        PasswordHistory hist = new PasswordHistory();
                        hist.UserId = customer.UserId;
                        hist.Password = customer.Password;
                        hist.PasswordSalt = customer.PasswordSalt;
                        hist.CreatedDate = DateTime.Now;

                        _contxt.PasswordHistory.Add(hist);
                        _contxt.SaveChanges();
                    }
                    catch (Exception e) {
                        return Json(new { status = false, message = "Error occured check your entries" });
                    }

                    /* 
                     * https://account.sendinblue.com/advanced/api
                     * 
                     */
                    try
                    {
                        string mailContent = string.Format("Hi {0} {1}", customer.FirstName, customer.LastName);
                        mailContent += ",<br/>Your registration completed successfully, Please confirm your email by clicking below link";
                        mailContent += string.Format("<br/><a href='http://localhost:56634/user/activateAccount?authToken={0}&userId={1}'>Confirm Email</a><br/>Thank you.", customer.AuthToken, customer.UserId);


                        MailMessage message = new MailMessage();
                        SmtpClient smtp = new SmtpClient();
                        message.From = new MailAddress("support@appsecurity.com");//from email
                        message.To.Add(new MailAddress(customer.Email));//customer.Email
                        message.Subject = "Appsecurity - Account activation";
                        message.IsBodyHtml = true; //to make message body as html  
                        message.Body = mailContent;
                        smtp.Port = 587;
                        smtp.Host = "smtp-relay.sendinblue.com"; //for gmail host  
                        smtp.EnableSsl = true;
                        smtp.UseDefaultCredentials = false;
                        smtp.Credentials = new NetworkCredential("rvmahesan@gmail.com", "SJgrkI9djbhnxmEB");
                        smtp.DeliveryMethod = SmtpDeliveryMethod.Network;
                        smtp.Send(message);

                    }
                    catch (Exception e)
                    {
                        var test = e.Message;
                    }

                    /* */

                    ViewData["errorMsg"] = "-NA-";
                    return Json(new { status = true, message = "Registration completed successfully! Confirmation email send" });
                }
                else
                {
                    return Json(new { status = false, message = errorMsg }); ;
                }
            }
            return Json(new { status = false, message = errorMsg }); ;
        }
        //step1:Get the user id
        //step2: Clear all temporary cart items ie, In Basket items
        //step3: Clear the session
        //step4: Redirect to login page
        public IActionResult logout()
        {
            try
            {
                int? userId = HttpContext.Session.GetInt32("userId");
                if (userId != 0)
                {
                    var login = HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                }

                HttpContext.Session.Clear();
            }
            catch (Exception e)
            {
                return RedirectToAction("login", "user");
            }
            return RedirectToAction("login", "user");
        }
    }
}

