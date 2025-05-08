namespace WebUI.Services
{
    public class AzureAdB2COptions
    {
        public string TenantId { get; set; }
        public string Instance { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Domain { get; set; }
        public string SignedOutCallbackPath { get; set; }
        public string SignUpSignInPolicyId { get; set; }
        public string SignInPolicyId { get; set; }
        public string SignUpPolicyId { get; set; }
        public string CallbackPath { get; set; }
        public string Authority { get; set; }
        public string ResetPasswordPolicyId { get; set; }
    }
}
