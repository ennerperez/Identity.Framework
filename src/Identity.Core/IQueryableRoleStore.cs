using System;
using System.Linq;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Interface that exposes an IQueryable roles
	/// </summary>
	/// <typeparam name="TRole"></typeparam>
	public interface IQueryableRoleStore<TRole> : IQueryableRoleStore<TRole, string>, IRoleStore<TRole, string>, IDisposable where TRole : IRole<string>
	{
	}
	/// <summary>
	///     Interface that exposes an IQueryable roles
	/// </summary>
	/// <typeparam name="TRole"></typeparam>
	/// <typeparam name="TKey"></typeparam>
	public interface IQueryableRoleStore<TRole, in TKey> : IRoleStore<TRole, TKey>, IDisposable where TRole : IRole<TKey>
	{
		/// <summary>
		///     IQueryable Roles
		/// </summary>
		IQueryable<TRole> Roles
		{
			get;
		}
	}
}
