using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

[Table("user_credentials")]
public class UserCredentials
{
    [Key]
    [Column("user_id")]
    public Guid UserId { get; set; }

    [Required]
    [Column("username")]
    public string Username { get; set; } = string.Empty;

    [Required]
    [Column("password_hash")]
    public byte[] PasswordHash { get; set; } = Array.Empty<byte>();


    [Required]
    [Column("password_salt")]
    public byte[] PasswordSalt { get; set; } = Array.Empty<byte>();
}
