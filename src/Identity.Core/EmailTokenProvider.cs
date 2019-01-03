using System;
using System.Globalization;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     TokenProvider that generates tokens from the user's security stamp and notifies a user via their email
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	public class EmailTokenProvider<TUser> : EmailTokenProvider<TUser, string> where TUser : class, IUser<string>
	{
	}
	/// <summary>
	///     TokenProvider that generates tokens from the user's security stamp and notifies a user via their email
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	/// <typeparam name="TKey"></typeparam>
	public class EmailTokenProvider<TUser, TKey> : TotpSecurityStampBasedTokenProvider<TUser, TKey> where TUser : class, IUser<TKey> where TKey : IEquatable<TKey>
	{
		private string _body;

		private string _subject;

		/// <summary>
		///     Email subject used when a token notification is received
		/// </summary>
		public string Subject
		{
			get
			{
				return _subject ?? string.Empty;
			}
			set
			{
				_subject = value;
			}
		}

		/// <summary>
		///     Email body which should contain a formatted string which the token will be the only argument
		/// </summary>
		public string BodyFormat
		{
			get
			{
				return _body ?? "{0}";
			}
			set
			{
				_body = value;
			}
		}

		/// <summary>
		///     True if the user has an email set
		/// </summary>
		/// <param name="manager"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public override async Task<bool> IsValidProviderForUserAsync(UserManager<TUser, TKey> manager, TUser user)
		{
			bool flag = !string.IsNullOrWhiteSpace(await TaskExtensions.WithCurrentCulture<string>(manager.GetEmailAsync(((IUser<TKey>)user).Id)));
			if (flag)
			{
				flag = await TaskExtensions.WithCurrentCulture<bool>(manager.IsEmailConfirmedAsync(((IUser<TKey>)user).Id));
			}
			return flag;
		}

		/// <summary>
		///     Returns the email of the user for entropy in the token
		/// </summary>
		/// <param name="purpose"></param>
		/// <param name="manager"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public override async Task<string> GetUserModifierAsync(string purpose, UserManager<TUser, TKey> manager, TUser user)
		{
			return "Email:" + purpose + ":" + await TaskExtensions.WithCurrentCulture<string>(manager.GetEmailAsync(((IUser<TKey>)user).Id));
		}

		/// <summary>
		///     Notifies the user with a token via email using the Subject and BodyFormat
		/// </summary>
		/// <param name="token"></param>
		/// <param name="manager"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public override Task NotifyAsync(string token, UserManager<TUser, TKey> manager, TUser user)
		{
			if (manager == null)
			{
				throw new ArgumentNullException("manager");
			}
			return manager.SendEmailAsync(user.Id, Subject, string.Format(CultureInfo.CurrentCulture, BodyFormat, new object[1]
			{
				token
			}));
		}
	}
}
