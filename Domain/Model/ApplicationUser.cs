using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Domain.Model
{
    [Table("ApplicationUser")]
    public class ApplicationUser : IdentityUser
    {

        [MaxLength(20)]
        //[Required(ErrorMessage = "First Name is required.")]
        [RegularExpression(@"^[a-zA-Z0-9]+$", ErrorMessage = "Name must be alphanumeric only.")]
        public string? FirstName { get; set; }

        //[Required(ErrorMessage = "Last Name is required.")]
        [RegularExpression(@"^[a-zA-Z0-9]+$", ErrorMessage = "Name must be alphanumeric only.")]
        [MaxLength(20)]
        public string? LastName { get; set; }

        //[ForeignKey(nameof(District))]
        //public int? DistrictId { get; set; }

        public DateTime LastLoginDateTime { get; set; } = DateTime.Now;

        [NotMapped]
        public string LastLoginDateTimeString { get { return LastLoginDateTime.ToString("d"); } }


        public string? IdProvider { get; set; }

        [DefaultValue(false)]
        public bool IsActive { get; set; }

        public string? UserDefinedStateAndDistrict { get; set; }

        //public virtual District District { get; set; }

        [NotMapped]
        public string FullNameAndEmail { get { return FirstName + " " + LastName + "," + Email; } }

        //[NotMapped]
        //public Application AccessGivenToApp { get; set; }

        [NotMapped]
        public string Applicationlist { get; set; }

        [NotMapped]
        public string StateDistrictName { get; set; }
        public string? TenantId { get; set; }
        
        // Session tracking for concurrent login prevention
        public string? SessionId { get; set; }
        public DateTime? LastSessionStartTime { get; set; }
    }
}
