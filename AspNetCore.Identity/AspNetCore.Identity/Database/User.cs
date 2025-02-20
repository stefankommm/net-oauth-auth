using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.Database;

public class User : IdentityUser
{
    public string? Initials { get; set; }
    
    [ProtectedPersonalData]
    [EmailAddress]
    [Required]
    public override string? Email { get; set; }  

     
}
