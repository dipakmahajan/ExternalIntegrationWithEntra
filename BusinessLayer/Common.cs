using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using System.Reflection.Metadata;

namespace BusinessLayer
{
    public static class Common
    {

        public const string AzureOffice365Account = "Azure,Office365";
        public const string LocalAccount = "Local";
        //public const string RoleSuperAdmin = "SuperAdmin";
        //public const string RoleAdmin = "Admin";
        //public const string RoleUser = "User";
       

        public static byte[] ConvertImagetoByte(string imageLocation)
        {
            return File.ReadAllBytes(imageLocation);
        }


        //public static async Task PassTokenInHeaderAsync(string accessToken,string externalAppUrl)
        //{
        //    //string externalAppUrl = "https://externalapp.com/page";

        //    using (HttpClient client = new HttpClient())
        //    {
        //        client.DefaultRequestHeaders.Authorization =
        //            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        //        HttpResponseMessage response = await client.GetAsync(externalAppUrl);

        //        if (response.IsSuccessStatusCode)
        //        {
        //            string content = await response.Content.ReadAsStringAsync();
        //            Console.WriteLine("Response received: " + content);
        //        }
        //        else
        //        {
        //            Console.WriteLine("Error: " + response.StatusCode);
        //        }
        //    }
        //}
        public static string HashRefreshToken(string token)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
                return Convert.ToBase64String(bytes);
            }
        }

        public static string GenerateURL(string baseURL, string path)
        {
            // Remove any trailing slashes from the base URL
            baseURL = baseURL.TrimEnd('/');

            // Remove any leading slashes from the path
            path = path.TrimStart('/');

            // Concatenate base URL and path with a single slash in between
            return $"{baseURL}/{path}";
        }
    }
}
