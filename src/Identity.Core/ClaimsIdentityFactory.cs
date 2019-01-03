using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
    /// <summary>
    ///     Creates a ClaimsIdentity from a User
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public class ClaimsIdentityFactory<TUser> : ClaimsIdentityFactory<TUser, string> where TUser : class, IUser<string>
    {
    }

    /// <summary>
    ///     Creates a ClaimsIdentity from a User
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public class ClaimsIdentityFactory<TUser, TKey> : IClaimsIdentityFactory<TUser, TKey> where TUser : class, IUser<TKey> where TKey : IEquatable<TKey>
    {
        internal const string IdentityProviderClaimType = "http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider";

        internal const string DefaultIdentityProviderClaimValue = "ASP.NET Identity";

        /// <summary>
        ///     Claim type used for role claims
        /// </summary>
        public string RoleClaimType
        {
            get;
            set;
        }

        /// <summary>
        ///     Claim type used for the user name
        /// </summary>
        public string UserNameClaimType
        {
            get;
            set;
        }

        /// <summary>
        ///     Claim type used for the user id
        /// </summary>
        public string UserIdClaimType
        {
            get;
            set;
        }

        /// <summary>
        ///     Claim type used for the user security stamp
        /// </summary>
        public string SecurityStampClaimType
        {
            get;
            set;
        }

        /// <summary>
        ///     Constructor
        /// </summary>
        public ClaimsIdentityFactory()
        {
            RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
            UserIdClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
            UserNameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
            SecurityStampClaimType = "Identity.SecurityStamp";
        }

        /// <summary>
        ///     Create a ClaimsIdentity from a user
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="user"></param>
        /// <param name="authenticationType"></param>
        /// <returns></returns>
        public virtual async Task<ClaimsIdentity> CreateAsync(UserManager<TUser, TKey> manager, TUser user, string authenticationType)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            ClaimsIdentity id = new ClaimsIdentity(authenticationType, this.UserNameClaimType, this.RoleClaimType);
            id.AddClaim(new Claim(this.UserIdClaimType, this.ConvertIdToString(((IUser<TKey>)user).Id), "http://www.w3.org/2001/XMLSchema#string"));
            id.AddClaim(new Claim(this.UserNameClaimType, ((IUser<TKey>)user).UserName, "http://www.w3.org/2001/XMLSchema#string"));
            id.AddClaim(new Claim("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider", "ASP.NET Identity", "http://www.w3.org/2001/XMLSchema#string"));
            if (manager.SupportsUserSecurityStamp)
            {
                ClaimsIdentity claimsIdentity = id;
                string securityStampClaimType = this.SecurityStampClaimType;
                Claim claim = new Claim(securityStampClaimType, await TaskExtensions.WithCurrentCulture<string>(manager.GetSecurityStampAsync(((IUser<TKey>)user).Id)));
                claimsIdentity.AddClaim(claim);
            }
            if (manager.SupportsUserRole)
            {
                foreach (string item in (IEnumerable<string>)(await TaskExtensions.WithCurrentCulture<IList<string>>(manager.GetRolesAsync(((IUser<TKey>)user).Id))))
                {
                    id.AddClaim(new Claim(this.RoleClaimType, item, "http://www.w3.org/2001/XMLSchema#string"));
                }
            }
            if (manager.SupportsUserClaim)
            {
                ClaimsIdentity claimsIdentity = id;
                claimsIdentity.AddClaims(await TaskExtensions.WithCurrentCulture<IList<Claim>>(manager.GetClaimsAsync(((IUser<TKey>)user).Id)));
            }
            return id;
        }

        /// <summary>
        ///     Convert the key to a string, by default just calls .ToString()
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public virtual string ConvertIdToString(TKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }
            return key.ToString();
        }
    }
}