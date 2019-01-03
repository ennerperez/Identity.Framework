using System;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Stores a user's password hash
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	public interface IUserPasswordStore<TUser> : IUserPasswordStore<TUser, string>, IUserStore<TUser, string>, IDisposable where TUser : class, IUser<string>
	{
	}
	/// <summary>
	///     Stores a user's password hash
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	/// <typeparam name="TKey"></typeparam>
	public interface IUserPasswordStore<TUser, in TKey> : IUserStore<TUser, TKey>, IDisposable where TUser : class, IUser<TKey>
	{
		/// <summary>
		///     Set the user password hash
		/// </summary>
		/// <param name="user"></param>
		/// <param name="passwordHash"></param>
		/// <returns></returns>
		Task SetPasswordHashAsync(TUser user, string passwordHash);

		/// <summary>
		///     Get the user password hash
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		Task<string> GetPasswordHashAsync(TUser user);

		/// <summary>
		///     Returns true if a user has a password set
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		Task<bool> HasPasswordAsync(TUser user);
	}
}
