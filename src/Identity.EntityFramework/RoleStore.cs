using System;
using System.Data.Entity;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
	public class RoleStore<TRole> : RoleStore<TRole, string, IdentityUserRole>, IQueryableRoleStore<TRole>, IQueryableRoleStore<TRole, string>, IRoleStore<TRole, string>, IDisposable where TRole : IdentityRole, new()
	{
		public RoleStore()
			: base((DbContext)new IdentityDbContext())
		{
			base.DisposeContext = true;
		}

		public RoleStore(DbContext context)
			: base(context)
		{
		}
	}
	public class RoleStore<TRole, TKey, TUserRole> : IQueryableRoleStore<TRole, TKey>, IRoleStore<TRole, TKey>, IDisposable where TRole : IdentityRole<TKey, TUserRole>, new()where TUserRole : IdentityUserRole<TKey>, new()
	{
		private bool _disposed;

		private EntityStore<TRole> _roleStore;

		public DbContext Context
		{
			get;
			private set;
		}

		public bool DisposeContext
		{
			get;
			set;
		}

		public IQueryable<TRole> Roles => _roleStore.EntitySet;

		public RoleStore(DbContext context)
		{
			if (context == null)
			{
				throw new ArgumentNullException("context");
			}
			Context = context;
			_roleStore = new EntityStore<TRole>(context);
		}

		public Task<TRole> FindByIdAsync(TKey roleId)
		{
			ThrowIfDisposed();
			return _roleStore.GetByIdAsync(roleId);
		}

		public Task<TRole> FindByNameAsync(string roleName)
		{
			ThrowIfDisposed();
			return QueryableExtensions.FirstOrDefaultAsync<TRole>(_roleStore.EntitySet, (Expression<Func<TRole, bool>>)((TRole u) => u.Name.ToUpper() == roleName.ToUpper()));
		}

		public virtual async Task CreateAsync(TRole role)
		{
			this.ThrowIfDisposed();
			if (role == null)
			{
				throw new ArgumentNullException("role");
			}
			this._roleStore.Create(role);
			await TaskExtensions.WithCurrentCulture<int>(this.Context.SaveChangesAsync());
		}

		public virtual async Task DeleteAsync(TRole role)
		{
			this.ThrowIfDisposed();
			if (role == null)
			{
				throw new ArgumentNullException("role");
			}
			this._roleStore.Delete(role);
			await TaskExtensions.WithCurrentCulture<int>(this.Context.SaveChangesAsync());
		}

		public virtual async Task UpdateAsync(TRole role)
		{
			this.ThrowIfDisposed();
			if (role == null)
			{
				throw new ArgumentNullException("role");
			}
			this._roleStore.Update(role);
			await TaskExtensions.WithCurrentCulture<int>(this.Context.SaveChangesAsync());
		}

		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		private void ThrowIfDisposed()
		{
			if (_disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
		}

		protected virtual void Dispose(bool disposing)
		{
			if ((DisposeContext & disposing) && Context != null)
			{
				Context.Dispose();
			}
			_disposed = true;
			Context = null;
			_roleStore = null;
		}
	}
}
