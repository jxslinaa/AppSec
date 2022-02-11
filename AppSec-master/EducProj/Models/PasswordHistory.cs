using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace AppSec.Models
{
    public class PasswordHistory
    {
        [Key]
        public int Id { get; set; }//Auto key customers unique id
        public int UserId { get; set; }//UserId
        public string Password { get; set; }
        public string PasswordSalt { get; set; }//Password matching key 
        public DateTime? CreatedDate { get; set; }
    }
}
