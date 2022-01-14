using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MinimalApiJwt.Entities;

namespace MinimalApiJwt.Persistance
{
    public class DbContext : IdentityDbContext<User>
    {

    }
}
