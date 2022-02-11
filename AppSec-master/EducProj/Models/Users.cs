using Microsoft.AspNetCore.Http;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AppSec.Models
{ 
    public class Users
    {
        [Key]
        public int UserId { get; set; }//Auto key customers unique id
        public String FirstName { get; set; }
        public String LastName { get; set; }
        public int isActive { get; set; }//We can disable the customer login details by this key
        public int FailedLogins { get; set; }//Store the failed login details
        public string Password { get; set; }
        public string PasswordSalt { get; set; }//Password matching key 
        public string Email { get; set; }//Unique field 
        public int EmailValidated { get; set; }
        public string MobileNumber { get; set; }
        public DateTime? CreatedDate { get; set; }
        public DateTime? LastLogin { get; set; }
        public DateTime? UpdatedDate { get; set; }
        public DateTime? LockOutEndDateUtc { get; set; }
        public int TwoFactorEnabled { get; set; }
        public string AuthToken { get; set; }
        public DateTime? PasswordExpiryUtc { get; set; }
        public byte[] ProfilePhoto { get; set; }
        public DateTime? DOB { get; set; }
        public string CardNumber { get; set; }
        public string CardExpiryDate { get; set; }
        public string CardCVV { get; set; }
        public string NameOnCard { get; set; }


        [NotMapped]
        public IFormFile Fileinps { get; set; }
        [NotMapped]
        public string c_password { get; set; }
    }
}
/** 
 * Table name - Customers - used to store the bookign details - ***/