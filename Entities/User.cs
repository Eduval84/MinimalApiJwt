using Microsoft.AspNetCore.Identity;

namespace MinimalApiJwt.Entities

{
    public class User :IdentityUser
    {
        public string? id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }


    }
}
