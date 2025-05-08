namespace WebUI.Models
{
    public class UserViewModel
    {
        public List<ModifiedApplication> ApplicationList { get; set; }
    }

    public class ModifiedApplication
    {

        public string AppName { get; set; }



        public byte[]? IconImageData { get; set; }



        public string DefaultUrl { get; set; }

        public string NavigationUrl { get; set; }

        public bool WithDefaultUrl { get; set; }


        public bool Active { get; set; }



        public int? DistrictId { get; set; }


    }
}
