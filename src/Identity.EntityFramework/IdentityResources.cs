using System.CodeDom.Compiler;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Resources;
using System.Runtime.CompilerServices;

namespace Microsoft.IdentityFramework
{
	[GeneratedCode("System.Resources.Tools.StronglyTypedResourceBuilder", "4.0.0.0")]
	[DebuggerNonUserCode]
	[CompilerGenerated]
	internal class IdentityResources
	{
		private static ResourceManager resourceMan;

		private static CultureInfo resourceCulture;

		[EditorBrowsable(EditorBrowsableState.Advanced)]
		internal static ResourceManager ResourceManager
		{
			get
			{
				if (resourceMan == null)
				{
					resourceMan = new ResourceManager("Microsoft.IdentityFramework.IdentityResources", typeof(IdentityResources).Assembly);
				}
				return resourceMan;
			}
		}

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

		internal static string DbValidationFailed => ResourceManager.GetString("DbValidationFailed", resourceCulture);

		internal static string DuplicateEmail => ResourceManager.GetString("DuplicateEmail", resourceCulture);

		internal static string DuplicateUserName => ResourceManager.GetString("DuplicateUserName", resourceCulture);

		internal static string EntityFailedValidation => ResourceManager.GetString("EntityFailedValidation", resourceCulture);

		internal static string ExternalLoginExists => ResourceManager.GetString("ExternalLoginExists", resourceCulture);

		internal static string IdentityV1SchemaError => ResourceManager.GetString("IdentityV1SchemaError", resourceCulture);

		internal static string IncorrectType => ResourceManager.GetString("IncorrectType", resourceCulture);

		internal static string PropertyCannotBeEmpty => ResourceManager.GetString("PropertyCannotBeEmpty", resourceCulture);

		internal static string RoleAlreadyExists => ResourceManager.GetString("RoleAlreadyExists", resourceCulture);

		internal static string RoleIsNotEmpty => ResourceManager.GetString("RoleIsNotEmpty", resourceCulture);

		internal static string RoleNotFound => ResourceManager.GetString("RoleNotFound", resourceCulture);

		internal static string UserAlreadyInRole => ResourceManager.GetString("UserAlreadyInRole", resourceCulture);

		internal static string UserIdNotFound => ResourceManager.GetString("UserIdNotFound", resourceCulture);

		internal static string UserLoginAlreadyExists => ResourceManager.GetString("UserLoginAlreadyExists", resourceCulture);

		internal static string UserNameNotFound => ResourceManager.GetString("UserNameNotFound", resourceCulture);

		internal static string UserNotInRole => ResourceManager.GetString("UserNotInRole", resourceCulture);

		internal static string ValueCannotBeNullOrEmpty => ResourceManager.GetString("ValueCannotBeNullOrEmpty", resourceCulture);

		internal IdentityResources()
		{
		}
	}
}
