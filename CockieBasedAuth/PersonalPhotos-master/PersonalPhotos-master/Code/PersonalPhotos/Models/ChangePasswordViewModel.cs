using System.ComponentModel.DataAnnotations;

namespace PersonalPhotos.Models
{
    public class ChangePasswordViewModel
    {
        [Required]
        public string Password { get; set; }
    }
}
