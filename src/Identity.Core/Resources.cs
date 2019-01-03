using System.CodeDom.Compiler;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Resources;
using System.Runtime.CompilerServices;

namespace Microsoft.IdentityFramework
{
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    [GeneratedCode("System.Resources.Tools.StronglyTypedResourceBuilder", "4.0.0.0")]
    [DebuggerNonUserCode]
    [CompilerGenerated]
    internal class Resources
    {
        private static ResourceManager resourceMan;

        private static CultureInfo resourceCulture;

        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        internal static ResourceManager ResourceManager
        {
            get
            {
                if (resourceMan == null)
                {
                    resourceMan = new ResourceManager("Microsoft.IdentityFramework.Resources", typeof(Resources).Assembly);
                }
                return resourceMan;
            }
        }

        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        internal static CultureInfo Culture
        {
            get
            {
                return resourceCulture;
            }
            set
            {
                resourceCulture = value;
            }
        }

        /// <summary>
        ///   Looks up a localized string similar to An unknown failure has occured..
        /// </summary>
        internal static string DefaultError => ResourceManager.GetString("DefaultError", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Email '{0}' is already taken..
        /// </summary>
        internal static string DuplicateEmail => ResourceManager.GetString("DuplicateEmail", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Name {0} is already taken..
        /// </summary>
        internal static string DuplicateName => ResourceManager.GetString("DuplicateName", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to A user with that external login already exists..
        /// </summary>
        internal static string ExternalLoginExists => ResourceManager.GetString("ExternalLoginExists", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Email '{0}' is invalid..
        /// </summary>
        internal static string InvalidEmail => ResourceManager.GetString("InvalidEmail", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Invalid token..
        /// </summary>
        internal static string InvalidToken => ResourceManager.GetString("InvalidToken", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to User name {0} is invalid, can only contain letters or digits..
        /// </summary>
        internal static string InvalidUserName => ResourceManager.GetString("InvalidUserName", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Lockout is not enabled for this user..
        /// </summary>
        internal static string LockoutNotEnabled => ResourceManager.GetString("LockoutNotEnabled", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to No IUserTokenProvider is registered..
        /// </summary>
        internal static string NoTokenProvider => ResourceManager.GetString("NoTokenProvider", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to No IUserTwoFactorProvider for '{0}' is registered..
        /// </summary>
        internal static string NoTwoFactorProvider => ResourceManager.GetString("NoTwoFactorProvider", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Incorrect password..
        /// </summary>
        internal static string PasswordMismatch => ResourceManager.GetString("PasswordMismatch", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Passwords must have at least one digit ('0'-'9')..
        /// </summary>
        internal static string PasswordRequireDigit => ResourceManager.GetString("PasswordRequireDigit", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Passwords must have at least one lowercase ('a'-'z')..
        /// </summary>
        internal static string PasswordRequireLower => ResourceManager.GetString("PasswordRequireLower", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Passwords must have at least one non letter or digit character..
        /// </summary>
        internal static string PasswordRequireNonLetterOrDigit => ResourceManager.GetString("PasswordRequireNonLetterOrDigit", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Passwords must have at least one uppercase ('A'-'Z')..
        /// </summary>
        internal static string PasswordRequireUpper => ResourceManager.GetString("PasswordRequireUpper", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Passwords must be at least {0} characters..
        /// </summary>
        internal static string PasswordTooShort => ResourceManager.GetString("PasswordTooShort", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to {0} cannot be null or empty..
        /// </summary>
        internal static string PropertyTooShort => ResourceManager.GetString("PropertyTooShort", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Role {0} does not exist..
        /// </summary>
        internal static string RoleNotFound => ResourceManager.GetString("RoleNotFound", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Store does not implement IQueryableRoleStore&lt;TRole&gt;..
        /// </summary>
        internal static string StoreNotIQueryableRoleStore => ResourceManager.GetString("StoreNotIQueryableRoleStore", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Store does not implement IQueryableUserStore&lt;TUser&gt;..
        /// </summary>
        internal static string StoreNotIQueryableUserStore => ResourceManager.GetString("StoreNotIQueryableUserStore", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Store does not implement IUserClaimStore&lt;TUser&gt;..
        /// </summary>
        internal static string StoreNotIUserClaimStore => ResourceManager.GetString("StoreNotIUserClaimStore", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Store does not implement IUserConfirmationStore&lt;TUser&gt;..
        /// </summary>
        internal static string StoreNotIUserConfirmationStore => ResourceManager.GetString("StoreNotIUserConfirmationStore", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Store does not implement IUserEmailStore&lt;TUser&gt;..
        /// </summary>
        internal static string StoreNotIUserEmailStore => ResourceManager.GetString("StoreNotIUserEmailStore", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Store does not implement IUserLockoutStore&lt;TUser&gt;..
        /// </summary>
        internal static string StoreNotIUserLockoutStore => ResourceManager.GetString("StoreNotIUserLockoutStore", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Store does not implement IUserLoginStore&lt;TUser&gt;..
        /// </summary>
        internal static string StoreNotIUserLoginStore => ResourceManager.GetString("StoreNotIUserLoginStore", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Store does not implement IUserPasswordStore&lt;TUser&gt;..
        /// </summary>
        internal static string StoreNotIUserPasswordStore => ResourceManager.GetString("StoreNotIUserPasswordStore", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Store does not implement IUserPhoneNumberStore&lt;TUser&gt;..
        /// </summary>
        internal static string StoreNotIUserPhoneNumberStore => ResourceManager.GetString("StoreNotIUserPhoneNumberStore", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Store does not implement IUserRoleStore&lt;TUser&gt;..
        /// </summary>
        internal static string StoreNotIUserRoleStore => ResourceManager.GetString("StoreNotIUserRoleStore", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Store does not implement IUserSecurityStampStore&lt;TUser&gt;..
        /// </summary>
        internal static string StoreNotIUserSecurityStampStore => ResourceManager.GetString("StoreNotIUserSecurityStampStore", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to Store does not implement IUserTwoFactorStore&lt;TUser&gt;..
        /// </summary>
        internal static string StoreNotIUserTwoFactorStore => ResourceManager.GetString("StoreNotIUserTwoFactorStore", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to User already has a password set..
        /// </summary>
        internal static string UserAlreadyHasPassword => ResourceManager.GetString("UserAlreadyHasPassword", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to User already in role..
        /// </summary>
        internal static string UserAlreadyInRole => ResourceManager.GetString("UserAlreadyInRole", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to UserId not found..
        /// </summary>
        internal static string UserIdNotFound => ResourceManager.GetString("UserIdNotFound", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to User {0} does not exist..
        /// </summary>
        internal static string UserNameNotFound => ResourceManager.GetString("UserNameNotFound", resourceCulture);

        /// <summary>
        ///   Looks up a localized string similar to User is not in role..
        /// </summary>
        internal static string UserNotInRole => ResourceManager.GetString("UserNotInRole", resourceCulture);

        internal Resources()
        {
        }
    }
}