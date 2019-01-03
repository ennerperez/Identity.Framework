using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Used to validate some basic password policy like length and number of non alphanumerics
	/// </summary>
	public class PasswordValidator : IIdentityValidator<string>
	{
		/// <summary>
		///     Minimum required length
		/// </summary>
		public int RequiredLength
		{
			get;
			set;
		}

		/// <summary>
		///     Require a non letter or digit character
		/// </summary>
		public bool RequireNonLetterOrDigit
		{
			get;
			set;
		}

		/// <summary>
		///     Require a lower case letter ('a' - 'z')
		/// </summary>
		public bool RequireLowercase
		{
			get;
			set;
		}

		/// <summary>
		///     Require an upper case letter ('A' - 'Z')
		/// </summary>
		public bool RequireUppercase
		{
			get;
			set;
		}

		/// <summary>
		///     Require a digit ('0' - '9')
		/// </summary>
		public bool RequireDigit
		{
			get;
			set;
		}

		/// <summary>
		///     Ensures that the string is of the required length and meets the configured requirements
		/// </summary>
		/// <param name="item"></param>
		/// <returns></returns>
		public virtual Task<IdentityResult> ValidateAsync(string item)
		{
			if (item == null)
			{
				throw new ArgumentNullException("item");
			}
			List<string> list = new List<string>();
			if (string.IsNullOrWhiteSpace(item) || item.Length < RequiredLength)
			{
				list.Add(string.Format(CultureInfo.CurrentCulture, Resources.PasswordTooShort, new object[1]
				{
					RequiredLength
				}));
			}
			if (RequireNonLetterOrDigit && item.All(IsLetterOrDigit))
			{
				list.Add(Resources.PasswordRequireNonLetterOrDigit);
			}
			if (RequireDigit && item.All((char c) => !IsDigit(c)))
			{
				list.Add(Resources.PasswordRequireDigit);
			}
			if (RequireLowercase && item.All((char c) => !IsLower(c)))
			{
				list.Add(Resources.PasswordRequireLower);
			}
			if (RequireUppercase && item.All((char c) => !IsUpper(c)))
			{
				list.Add(Resources.PasswordRequireUpper);
			}
			if (list.Count == 0)
			{
				return Task.FromResult(IdentityResult.Success);
			}
			return Task.FromResult(IdentityResult.Failed(string.Join(" ", list)));
		}

		/// <summary>
		///     Returns true if the character is a digit between '0' and '9'
		/// </summary>
		/// <param name="c"></param>
		/// <returns></returns>
		public virtual bool IsDigit(char c)
		{
			if (c >= '0')
			{
				return c <= '9';
			}
			return false;
		}

		/// <summary>
		///     Returns true if the character is between 'a' and 'z'
		/// </summary>
		/// <param name="c"></param>
		/// <returns></returns>
		public virtual bool IsLower(char c)
		{
			if (c >= 'a')
			{
				return c <= 'z';
			}
			return false;
		}

		/// <summary>
		///     Returns true if the character is between 'A' and 'Z'
		/// </summary>
		/// <param name="c"></param>
		/// <returns></returns>
		public virtual bool IsUpper(char c)
		{
			if (c >= 'A')
			{
				return c <= 'Z';
			}
			return false;
		}

		/// <summary>
		///     Returns true if the character is upper, lower, or a digit
		/// </summary>
		/// <param name="c"></param>
		/// <returns></returns>
		public virtual bool IsLetterOrDigit(char c)
		{
			if (!IsUpper(c) && !IsLower(c))
			{
				return IsDigit(c);
			}
			return true;
		}
	}
}
