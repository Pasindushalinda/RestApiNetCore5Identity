using System.ComponentModel.DataAnnotations;

namespace TodoApp.Data.Dtos
{
    public class UserRegistrationDto
    {
        public string Username { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}