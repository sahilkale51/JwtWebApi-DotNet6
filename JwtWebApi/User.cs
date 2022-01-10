namespace JwtWebApi
{
    public class User
    {
        public int Id { get; set; }
        public string userName { get; set; } = string.Empty;
        public byte[] passwordSalt { get; set; }
        public byte[] passwordHash { get; set; }
    }
}
