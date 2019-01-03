using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Stores user specific claims
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	public interface IUserClaimStore<TUser> : IUserClaimStore<TUser, string>, IUserStore<TUser, string>, IDisposable where TUser : class, IUser<string>
	{
	}
	/// <summary>
	///     Stores user specific claims
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	/// <typeparam name="TKey"></typeparam>
	public interface IUserClaimStore<TUser, in TKey> : IUserStore<TUser, TKey>, IDisposable where TUser : class, IUser<TKey>
	{
		/// <summary>
		///     Returns the claims for the user with the issuer set
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		Task<IList<Claim>> GetClaimsAsync(TUser user);

		/// <summary>
		///     Add a new user claim
		/// </summary>
		/// <param name="user"></param>
		/// <param name="claim"></param>
		/// <returns></returns>
		Task AddClaimAsync(TUser user, Claim claim);

		/// <summary>
		///     Remove a user claim
		/// </summary>
		/// <param name="user"></param>
		/// <param name="claim"></param>
		/// <returns></returns>
		Task RemoveClaimAsync(TUser user, Claim claim);
	}
}
