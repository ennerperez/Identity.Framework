using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Validates roles before they are saved
	/// </summary>
	/// <typeparam name="TRole"></typeparam>
	public class RoleValidator<TRole> : RoleValidator<TRole, string> where TRole : class, IRole<string>
	{
		/// <summary>
		///     Constructor
		/// </summary>
		/// <param name="manager"></param>
		public RoleValidator(RoleManager<TRole, string> manager)
			: base(manager)
		{
		}
	}
	/// <summary>
	///     Validates roles before they are saved
	/// </summary>
	/// <typeparam name="TRole"></typeparam>
	/// <typeparam name="TKey"></typeparam>
	public class RoleValidator<TRole, TKey> : IIdentityValidator<TRole> where TRole : class, IRole<TKey> where TKey : IEquatable<TKey>
	{
		private RoleManager<TRole, TKey> Manager
		{
			get;
			set;
		}

		/// <summary>
		///     Constructor
		/// </summary>
		/// <param name="manager"></param>
		public RoleValidator(RoleManager<TRole, TKey> manager)
		{
			if (manager == null)
			{
				throw new ArgumentNullException("manager");
			}
			Manager = manager;
		}

		/// <summary>
		///     Validates a role before saving
		/// </summary>
		/// <param name="item"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> ValidateAsync(TRole item)
		{
			if (item == null)
			{
				throw new ArgumentNullException("item");
			}
			List<string> errors = new List<string>();
			await this.ValidateRoleName(item, errors).WithCurrentCulture();
			if (errors.Count > 0)
			{
				return IdentityResult.Failed(errors.ToArray());
			}
			return IdentityResult.Success;
		}

		private async Task ValidateRoleName(TRole role, List<string> errors)
		{
			if (string.IsNullOrWhiteSpace(((IRole<TKey>)role).Name))
			{
				errors.Add(string.Format(CultureInfo.CurrentCulture, Resources.PropertyTooShort, new object[1]
				{
					"Name"
				}));
			}
			else
			{
				TRole val = await TaskExtensions.WithCurrentCulture<TRole>(this.Manager.FindByNameAsync(((IRole<TKey>)role).Name));
				if (val != null && !EqualityComparer<TKey>.Default.Equals(((IRole<TKey>)val).Id, ((IRole<TKey>)role).Id))
				{
					errors.Add(string.Format(CultureInfo.CurrentCulture, Resources.DuplicateName, new object[1]
					{
						((IRole<TKey>)role).Name
					}));
				}
			}
		}
	}
}
