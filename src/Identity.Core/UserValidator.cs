using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Mail;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Validates users before they are saved
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	public class UserValidator<TUser> : UserValidator<TUser, string> where TUser : class, IUser<string>
	{
		/// <summary>
		///     Constructor
		/// </summary>
		/// <param name="manager"></param>
		public UserValidator(UserManager<TUser, string> manager)
			: base(manager)
		{
		}
	}
	/// <summary>
	///     Validates users before they are saved
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	/// <typeparam name="TKey"></typeparam>
	public class UserValidator<TUser, TKey> : IIdentityValidator<TUser> where TUser : class, IUser<TKey> where TKey : IEquatable<TKey>
	{
		/// <summary>
		///     Only allow [A-Za-z0-9@_] in UserNames
		/// </summary>
		public bool AllowOnlyAlphanumericUserNames
		{
			get;
			set;
		}

		/// <summary>
		///     If set, enforces that emails are non empty, valid, and unique
		/// </summary>
		public bool RequireUniqueEmail
		{
			get;
			set;
		}

		private UserManager<TUser, TKey> Manager
		{
			get;
			set;
		}

		/// <summary>
		///     Constructor
		/// </summary>
		/// <param name="manager"></param>
		public UserValidator(UserManager<TUser, TKey> manager)
		{
			if (manager == null)
			{
				throw new ArgumentNullException("manager");
			}
			AllowOnlyAlphanumericUserNames = true;
			Manager = manager;
		}

		/// <summary>
		///     Validates a user before saving
		/// </summary>
		/// <param name="item"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> ValidateAsync(TUser item)
		{
			if (item == null)
			{
				throw new ArgumentNullException("item");
			}
			List<string> errors = new List<string>();
			await this.ValidateUserName(item, errors).WithCurrentCulture();
			if (this.RequireUniqueEmail)
			{
				await this.ValidateEmailAsync(item, errors).WithCurrentCulture();
			}
			if (errors.Count > 0)
			{
				return IdentityResult.Failed(errors.ToArray());
			}
			return IdentityResult.Success;
		}

		private async Task ValidateUserName(TUser user, List<string> errors)
		{
			if (string.IsNullOrWhiteSpace(((IUser<TKey>)user).UserName))
			{
				errors.Add(string.Format(CultureInfo.CurrentCulture, Resources.PropertyTooShort, new object[1]
				{
					"Name"
				}));
			}
			else if (this.AllowOnlyAlphanumericUserNames && !Regex.IsMatch(((IUser<TKey>)user).UserName, "^[A-Za-z0-9@_\\.]+$"))
			{
				errors.Add(string.Format(CultureInfo.CurrentCulture, Resources.InvalidUserName, new object[1]
				{
					((IUser<TKey>)user).UserName
				}));
			}
			else
			{
				TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.Manager.FindByNameAsync(((IUser<TKey>)user).UserName));
				if (val != null && !EqualityComparer<TKey>.Default.Equals(((IUser<TKey>)val).Id, ((IUser<TKey>)user).Id))
				{
					errors.Add(string.Format(CultureInfo.CurrentCulture, Resources.DuplicateName, new object[1]
					{
						((IUser<TKey>)user).UserName
					}));
				}
			}
		}

		private async Task ValidateEmailAsync(TUser user, List<string> errors)
		{
			string email = await TaskExtensions.WithCurrentCulture<string>(this.Manager.GetEmailStore().GetEmailAsync(user));
			if (string.IsNullOrWhiteSpace(email))
			{
				errors.Add(string.Format(CultureInfo.CurrentCulture, Resources.PropertyTooShort, new object[1]
				{
					"Email"
				}));
			}
			else
			{
				try
				{
					new MailAddress(email);
				}
				catch (FormatException)
				{
					errors.Add(string.Format(CultureInfo.CurrentCulture, Resources.InvalidEmail, new object[1]
					{
						email
					}));
					return;
				}
				TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.Manager.FindByEmailAsync(email));
				if (val != null && !EqualityComparer<TKey>.Default.Equals(((IUser<TKey>)val).Id, ((IUser<TKey>)user).Id))
				{
					errors.Add(string.Format(CultureInfo.CurrentCulture, Resources.DuplicateEmail, new object[1]
					{
						email
					}));
				}
			}
		}
	}
}
