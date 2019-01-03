using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Interface that maps users to their roles
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	public interface IUserRoleStore<TUser> : IUserRoleStore<TUser, string>, IUserStore<TUser, string>, IDisposable where TUser : class, IUser<string>
	{
	}
	/// <summary>
	///     Interface that maps users to their roles
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	/// <typeparam name="TKey"></typeparam>
	public interface IUserRoleStore<TUser, in TKey> : IUserStore<TUser, TKey>, IDisposable where TUser : class, IUser<TKey>
	{
		/// <summary>
		///     Adds a user to a role
		/// </summary>
		/// <param name="user"></param>
		/// <param name="roleName"></param>
		/// <returns></returns>
		Task AddToRoleAsync(TUser user, string roleName);

		/// <summary>
		///     Removes the role for the user
		/// </summary>
		/// <param name="user"></param>
		/// <param name="roleName"></param>
		/// <returns></returns>
		Task RemoveFromRoleAsync(TUser user, string roleName);

		/// <summary>
		///     Returns the roles for this user
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		Task<IList<string>> GetRolesAsync(TUser user);

		/// <summary>
		///     Returns true if a user is in the role
		/// </summary>
		/// <param name="user"></param>
		/// <param name="roleName"></param>
		/// <returns></returns>
		Task<bool> IsInRoleAsync(TUser user, string roleName);
	}
}
