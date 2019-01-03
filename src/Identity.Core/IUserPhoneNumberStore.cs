using System;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Stores a user's phone number
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	public interface IUserPhoneNumberStore<TUser> : IUserPhoneNumberStore<TUser, string>, IUserStore<TUser, string>, IDisposable where TUser : class, IUser<string>
	{
	}
	/// <summary>
	///     Stores a user's phone number
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	/// <typeparam name="TKey"></typeparam>
	public interface IUserPhoneNumberStore<TUser, in TKey> : IUserStore<TUser, TKey>, IDisposable where TUser : class, IUser<TKey>
	{
		/// <summary>
		///     Set the user's phone number
		/// </summary>
		/// <param name="user"></param>
		/// <param name="phoneNumber"></param>
		/// <returns></returns>
		Task SetPhoneNumberAsync(TUser user, string phoneNumber);

		/// <summary>
		///     Get the user phone number
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		Task<string> GetPhoneNumberAsync(TUser user);

		/// <summary>
		///     Returns true if the user phone number is confirmed
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		Task<bool> GetPhoneNumberConfirmedAsync(TUser user);

		/// <summary>
		///     Sets whether the user phone number is confirmed
		/// </summary>
		/// <param name="user"></param>
		/// <param name="confirmed"></param>
		/// <returns></returns>
		Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed);
	}
}
