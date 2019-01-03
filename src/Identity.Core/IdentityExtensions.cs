using System;
using System.Globalization;
using System.Security.Claims;
using System.Security.Principal;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Extensions making it easier to get the user name/user id claims off of an identity
	/// </summary>
	public static class IdentityExtensions
	{
		/// <summary>
		///     Return the user name using the UserNameClaimType
		/// </summary>
		/// <param name="identity"></param>
		/// <returns></returns>
		public static string GetUserName(this IIdentity identity)
		{
			if (identity == null)
			{
				throw new ArgumentNullException("identity");
			}
			return (identity as ClaimsIdentity)?.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name");
		}

		/// <summary>
		///     Return the user id using the UserIdClaimType
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="identity"></param>
		/// <returns></returns>
		public static T GetUserId<T>(this IIdentity identity) where T : IConvertible
		{
			if (identity == null)
			{
				throw new ArgumentNullException("identity");
			}
			ClaimsIdentity claimsIdentity = identity as ClaimsIdentity;
			if (claimsIdentity != null)
			{
				string text = claimsIdentity.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
				if (text != null)
				{
					return (T)Convert.ChangeType(text, typeof(T), CultureInfo.InvariantCulture);
				}
			}
			return default(T);
		}

		/// <summary>
		///     Return the user id using the UserIdClaimType
		/// </summary>
		/// <param name="identity"></param>
		/// <returns></returns>
		public static string GetUserId(this IIdentity identity)
		{
			if (identity == null)
			{
				throw new ArgumentNullException("identity");
			}
			return (identity as ClaimsIdentity)?.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
		}

		/// <summary>
		///     Return the claim value for the first claim with the specified type if it exists, null otherwise
		/// </summary>
		/// <param name="identity"></param>
		/// <param name="claimType"></param>
		/// <returns></returns>
		public static string FindFirstValue(this ClaimsIdentity identity, string claimType)
		{
			if (identity == null)
			{
				throw new ArgumentNullException("identity");
			}
			return identity.FindFirst(claimType)?.Value;
		}
	}
}
