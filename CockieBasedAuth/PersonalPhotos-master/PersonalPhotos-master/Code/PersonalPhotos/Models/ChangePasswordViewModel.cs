using System.ComponentModel.DataAnnotations;

namespace PersonalPhotos.Models
{
    public class ChangePasswordViewModel
    {
        [Required]
        public string EmailAddress { get; set; }

        [Required]
        public string Password { get; set; }

        public string Token { get; set; }
    }
}
