using System;
using System.Linq;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Interface that exposes an IQueryable users
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	public interface IQueryableUserStore<TUser> : IQueryableUserStore<TUser, string>, IUserStore<TUser, string>, IDisposable where TUser : class, IUser<string>
	{
	}
	/// <summary>
	///     Interface that exposes an IQueryable users
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	/// <typeparam name="TKey"></typeparam>
	public interface IQueryableUserStore<TUser, in TKey> : IUserStore<TUser, TKey>, IDisposable where TUser : class, IUser<TKey>
	{
		/// <summary>
		///     IQueryable users
		/// </summary>
		IQueryable<TUser> Users
		{
			get;
		}
	}
}
