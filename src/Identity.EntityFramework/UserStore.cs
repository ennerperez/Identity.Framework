using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
    /// <summary>Implements IUserStore using EntityFramework where TUser is the entity type of the user being stored</summary>
    /// <typeparam name="TUser"></typeparam>
    public class UserStore<TUser> : UserStore<TUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>, IUserStore<TUser>, IUserStore<TUser, string>, IDisposable where TUser : IdentityUser
    {
        public UserStore()
            : this((DbContext)new IdentityDbContext())
        {
            base.DisposeContext = true;
        }

        /// <summary>Constructor that takes the db context</summary>
        public UserStore(DbContext context)
            : base(context)
        {
        }
    }

    public class UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim> : IUserLoginStore<TUser, TKey>, IUserStore<TUser, TKey>, IDisposable, IUserClaimStore<TUser, TKey>, IUserRoleStore<TUser, TKey>, IUserPasswordStore<TUser, TKey>, IUserSecurityStampStore<TUser, TKey>, IQueryableUserStore<TUser, TKey>, IUserEmailStore<TUser, TKey>, IUserPhoneNumberStore<TUser, TKey>, IUserTwoFactorStore<TUser, TKey>, IUserLockoutStore<TUser, TKey> where TUser : IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim> where TRole : IdentityRole<TKey, TUserRole> where TKey : IEquatable<TKey> where TUserLogin : IdentityUserLogin<TKey>, new() where TUserRole : IdentityUserRole<TKey>, new() where TUserClaim : IdentityUserClaim<TKey>, new()
    {
        private static class FindByIdFilterParser
        {
            private static readonly Expression<Func<TUser, bool>> Predicate = (TUser u) => u.Id.Equals(default(TKey));

            private static readonly MethodInfo EqualsMethodInfo = ((MethodCallExpression)Predicate.Body).Method;

            private static readonly MemberInfo UserIdMemberInfo = ((MemberExpression)((MethodCallExpression)Predicate.Body).Object).Member;

            internal static bool TryMatchAndGetId(Expression<Func<TUser, bool>> filter, out TKey id)
            {
                id = default(TKey);
                if (filter.Body.NodeType != ExpressionType.Call)
                {
                    return false;
                }
                MethodCallExpression methodCallExpression = (MethodCallExpression)filter.Body;
                if (methodCallExpression.Method != EqualsMethodInfo)
                {
                    return false;
                }
                if (methodCallExpression.Object == null || methodCallExpression.Object.NodeType != ExpressionType.MemberAccess || ((MemberExpression)methodCallExpression.Object).Member != UserIdMemberInfo)
                {
                    return false;
                }
                if (methodCallExpression.Arguments.Count != 1)
                {
                    return false;
                }
                MemberExpression memberExpression;
                if (methodCallExpression.Arguments[0].NodeType == ExpressionType.Convert)
                {
                    UnaryExpression unaryExpression = (UnaryExpression)methodCallExpression.Arguments[0];
                    if (unaryExpression.Operand.NodeType != ExpressionType.MemberAccess)
                    {
                        return false;
                    }
                    memberExpression = (MemberExpression)unaryExpression.Operand;
                }
                else
                {
                    if (methodCallExpression.Arguments[0].NodeType != ExpressionType.MemberAccess)
                    {
                        return false;
                    }
                    memberExpression = (MemberExpression)methodCallExpression.Arguments[0];
                }
                if (memberExpression.Member.MemberType != MemberTypes.Field || memberExpression.Expression.NodeType != ExpressionType.Constant)
                {
                    return false;
                }
                FieldInfo fieldInfo = (FieldInfo)memberExpression.Member;
                object value = ((ConstantExpression)memberExpression.Expression).Value;
                id = (TKey)fieldInfo.GetValue(value);
                return true;
            }
        }

        private readonly IDbSet<TUserLogin> _logins;

        private readonly EntityStore<TRole> _roleStore;

        private readonly IDbSet<TUserClaim> _userClaims;

        private readonly IDbSet<TUserRole> _userRoles;

        private bool _disposed;

        private EntityStore<TUser> _userStore;

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

        public bool AutoSaveChanges
        {
            get;
            set;
        }

        public IQueryable<TUser> Users => _userStore.EntitySet;

        public UserStore(DbContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            Context = context;
            AutoSaveChanges = true;
            _userStore = new EntityStore<TUser>(context);
            _roleStore = new EntityStore<TRole>(context);
            _logins = Context.Set<TUserLogin>();
            _userClaims = Context.Set<TUserClaim>();
            _userRoles = Context.Set<TUserRole>();
        }

        public virtual async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            await this.EnsureClaimsLoaded(user).WithCurrentCulture();
            return Enumerable.ToList<Claim>(Enumerable.Select<TUserClaim, Claim>((IEnumerable<TUserClaim>)((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Claims, (Func<TUserClaim, Claim>)((TUserClaim c) => new Claim(((IdentityUserClaim<TKey>)c).ClaimType, ((IdentityUserClaim<TKey>)c).ClaimValue))));
        }

        public virtual Task AddClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }
            IDbSet<TUserClaim> userClaims = _userClaims;
            TUserClaim val = new TUserClaim();
            val.UserId = user.Id;
            val.ClaimType = claim.Type;
            val.ClaimValue = claim.Value;
            userClaims.Add(val);
            return Task.FromResult<int>(0);
        }

        public virtual async Task RemoveClaimAsync(TUser user, Claim claim)
        {
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }
            string claimValue = claim.Value;
            string claimType = claim.Type;
            IEnumerable<TUserClaim> enumerable;
            if (this.AreClaimsLoaded(user))
            {
                enumerable = Enumerable.ToList<TUserClaim>(Enumerable.Where<TUserClaim>((IEnumerable<TUserClaim>)((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Claims, (Func<TUserClaim, bool>)delegate (TUserClaim uc)
                {
                    if (((IdentityUserClaim<TKey>)uc).ClaimValue == claimValue)
                    {
                        return ((IdentityUserClaim<TKey>)uc).ClaimType == claimType;
                    }
                    return false;
                }));
            }
            else
            {
                TKey userId = ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Id;
                enumerable = await TaskExtensions.WithCurrentCulture<List<TUserClaim>>(QueryableExtensions.ToListAsync<TUserClaim>(Queryable.Where<TUserClaim>((IQueryable<TUserClaim>)this._userClaims, (Expression<Func<TUserClaim, bool>>)((TUserClaim uc) => ((IdentityUserClaim<TKey>)uc).ClaimValue == claimValue && ((IdentityUserClaim<TKey>)uc).ClaimType == claimType && ((IEquatable<TKey>)((IdentityUserClaim<TKey>)uc).UserId).Equals(userId)))));
            }
            foreach (TUserClaim item in enumerable)
            {
                this._userClaims.Remove(item);
            }
        }

        public virtual Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult<bool>(user.EmailConfirmed);
        }

        public virtual Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.EmailConfirmed = confirmed;
            return Task.FromResult<int>(0);
        }

        public virtual Task SetEmailAsync(TUser user, string email)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.Email = email;
            return Task.FromResult<int>(0);
        }

        public virtual Task<string> GetEmailAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult<string>(user.Email);
        }

        public virtual Task<TUser> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();
            return GetUserAggregateAsync((TUser u) => u.Email.ToUpper() == email.ToUpper());
        }

        public virtual Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult<DateTimeOffset>(user.LockoutEndDateUtc.HasValue ? new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc)) : default(DateTimeOffset));
        }

        public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.LockoutEndDateUtc = ((lockoutEnd == DateTimeOffset.MinValue) ? null : new DateTime?(lockoutEnd.UtcDateTime));
            return Task.FromResult<int>(0);
        }

        public virtual Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.AccessFailedCount++;
            return Task.FromResult<int>(user.AccessFailedCount);
        }

        public virtual Task ResetAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.AccessFailedCount = 0;
            return Task.FromResult<int>(0);
        }

        public virtual Task<int> GetAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult<int>(user.AccessFailedCount);
        }

        public virtual Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult<bool>(user.LockoutEnabled);
        }

        public virtual Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.LockoutEnabled = enabled;
            return Task.FromResult<int>(0);
        }

        public virtual Task<TUser> FindByIdAsync(TKey userId)
        {
            ThrowIfDisposed();
            return GetUserAggregateAsync((TUser u) => u.Id.Equals(userId));
        }

        public virtual Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();
            return GetUserAggregateAsync((TUser u) => u.UserName.ToUpper() == userName.ToUpper());
        }

        public virtual async Task CreateAsync(TUser user)
        {
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            this._userStore.Create(user);
            await this.SaveChanges().WithCurrentCulture();
        }

        public virtual async Task DeleteAsync(TUser user)
        {
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            this._userStore.Delete(user);
            await this.SaveChanges().WithCurrentCulture();
        }

        public virtual async Task UpdateAsync(TUser user)
        {
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            this._userStore.Update(user);
            await this.SaveChanges().WithCurrentCulture();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public virtual async Task<TUser> FindAsync(UserLoginInfo login)
        {
            throw new NotImplementedException("LdMemberToken");
            //this.ThrowIfDisposed();
            //if (login == null)
            //{
            //    throw new ArgumentNullException("login");
            //}
            //string provider = login.LoginProvider;
            //string key = login.ProviderKey;
            //TUserLogin val = await TaskExtensions.WithCurrentCulture<TUserLogin>(QueryableExtensions.FirstOrDefaultAsync<TUserLogin>((IQueryable<TUserLogin>)this._logins, (Expression<Func<TUserLogin, bool>>)((TUserLogin l) => ((IdentityUserLogin<TKey>)l).LoginProvider == provider && ((IdentityUserLogin<TKey>)l).ProviderKey == key)));
            //if (val != null)
            //{
            //    TKey userId = ((IdentityUserLogin<TKey>)val).UserId;
            //    ParameterExpression parameterExpression = Expression.Parameter(typeof(TUser), "u");
            //    _003C_003Ec__DisplayClass42_1 value;
            //    return await TaskExtensions.WithCurrentCulture<TUser>(this.GetUserAggregateAsync(Expression.Lambda<Func<TUser, bool>>((Expression)Expression.Call(Expression.Property(parameterExpression, (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>).TypeHandle)), (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IEquatable<TKey>).TypeHandle), Expression.Field(Expression.Constant(value, typeof(_003C_003Ec__DisplayClass42_1)), FieldInfo.GetFieldFromHandle((RuntimeFieldHandle)/*OpCode not supported: LdMemberToken*/, typeof(_003C_003Ec__DisplayClass42_1).TypeHandle))), new ParameterExpression[1]
            //    {
            //        parameterExpression
            //    })));
            //}
            //return null;
        }

        public virtual Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }
            IDbSet<TUserLogin> logins = _logins;
            TUserLogin val = new TUserLogin();
            val.UserId = user.Id;
            val.ProviderKey = login.ProviderKey;
            val.LoginProvider = login.LoginProvider;
            logins.Add(val);
            return Task.FromResult<int>(0);
        }

        public virtual async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }
            string provider = login.LoginProvider;
            string key = login.ProviderKey;
            TUserLogin val;
            if (this.AreLoginsLoaded(user))
            {
                val = Enumerable.SingleOrDefault<TUserLogin>((IEnumerable<TUserLogin>)((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Logins, (Func<TUserLogin, bool>)delegate (TUserLogin ul)
                {
                    if (((IdentityUserLogin<TKey>)ul).LoginProvider == provider)
                    {
                        return ((IdentityUserLogin<TKey>)ul).ProviderKey == key;
                    }
                    return false;
                });
            }
            else
            {
                TKey userId = ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Id;
                val = await TaskExtensions.WithCurrentCulture<TUserLogin>(QueryableExtensions.SingleOrDefaultAsync<TUserLogin>((IQueryable<TUserLogin>)this._logins, (Expression<Func<TUserLogin, bool>>)((TUserLogin ul) => ((IdentityUserLogin<TKey>)ul).LoginProvider == provider && ((IdentityUserLogin<TKey>)ul).ProviderKey == key && ((IEquatable<TKey>)((IdentityUserLogin<TKey>)ul).UserId).Equals(userId))));
            }
            if (val != null)
            {
                this._logins.Remove(val);
            }
        }

        public virtual async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            await this.EnsureLoginsLoaded(user).WithCurrentCulture();
            return Enumerable.ToList<UserLoginInfo>(Enumerable.Select<TUserLogin, UserLoginInfo>((IEnumerable<TUserLogin>)((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Logins, (Func<TUserLogin, UserLoginInfo>)((TUserLogin l) => new UserLoginInfo(((IdentityUserLogin<TKey>)l).LoginProvider, ((IdentityUserLogin<TKey>)l).ProviderKey))));
        }

        public virtual Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.PasswordHash = passwordHash;
            return Task.FromResult<int>(0);
        }

        public virtual Task<string> GetPasswordHashAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult<string>(user.PasswordHash);
        }

        public virtual Task<bool> HasPasswordAsync(TUser user)
        {
            return Task.FromResult<bool>(user.PasswordHash != null);
        }

        public virtual Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.PhoneNumber = phoneNumber;
            return Task.FromResult<int>(0);
        }

        public virtual Task<string> GetPhoneNumberAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult<string>(user.PhoneNumber);
        }

        public virtual Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult<bool>(user.PhoneNumberConfirmed);
        }

        public virtual Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.PhoneNumberConfirmed = confirmed;
            return Task.FromResult<int>(0);
        }

        public virtual async Task AddToRoleAsync(TUser user, string roleName)
        {
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, "roleName");
            }
            TRole val = await TaskExtensions.WithCurrentCulture<TRole>(QueryableExtensions.SingleOrDefaultAsync<TRole>((IQueryable<TRole>)this._roleStore.DbEntitySet, (Expression<Func<TRole, bool>>)((TRole r) => ((IdentityRole<TKey, TUserRole>)r).Name.ToUpper() == roleName.ToUpper())));
            if (val == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, IdentityResources.RoleNotFound, new object[1]
                {
                    roleName
                }));
            }
            TUserRole val2 = new TUserRole();
            ((IdentityUserRole<TKey>)val2).UserId = ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Id;
            ((IdentityUserRole<TKey>)val2).RoleId = ((IdentityRole<TKey, TUserRole>)val).Id;
            TUserRole entity = val2;
            this._userRoles.Add(entity);
        }

        public virtual async Task RemoveFromRoleAsync(TUser user, string roleName)
        {
            throw new NotImplementedException("LdMemberToken");
            //this.ThrowIfDisposed();
            //if (user == null)
            //{
            //    throw new ArgumentNullException("user");
            //}
            //if (string.IsNullOrWhiteSpace(roleName))
            //{
            //    throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, "roleName");
            //}
            //TRole val = await TaskExtensions.WithCurrentCulture<TRole>(QueryableExtensions.SingleOrDefaultAsync<TRole>((IQueryable<TRole>)this._roleStore.DbEntitySet, (Expression<Func<TRole, bool>>)((TRole r) => ((IdentityRole<TKey, TUserRole>)r).Name.ToUpper() == roleName.ToUpper())));
            //if (val != null)
            //{
            //    TKey roleId = ((IdentityRole<TKey, TUserRole>)val).Id;
            //    TKey userId = ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Id;
            //    IDbSet<TUserRole> userRoles = this._userRoles;
            //    ParameterExpression parameterExpression = Expression.Parameter(typeof(TUserRole), "r");
            //    _003C_003Ec__DisplayClass54_1 value;
            //    TUserRole val2 = await TaskExtensions.WithCurrentCulture<TUserRole>(QueryableExtensions.FirstOrDefaultAsync<TUserRole>((IQueryable<TUserRole>)userRoles, Expression.Lambda<Func<TUserRole, bool>>((Expression)Expression.AndAlso(Expression.Call(Expression.Field(Expression.Constant(value, typeof(_003C_003Ec__DisplayClass54_1)), FieldInfo.GetFieldFromHandle((RuntimeFieldHandle)/*OpCode not supported: LdMemberToken*/, typeof(_003C_003Ec__DisplayClass54_1).TypeHandle)), (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IEquatable<TKey>).TypeHandle), Expression.Property(parameterExpression, (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IdentityUserRole<TKey>).TypeHandle))), Expression.Call(Expression.Property(parameterExpression, (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IdentityUserRole<TKey>).TypeHandle)), (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IEquatable<TKey>).TypeHandle), Expression.Field(Expression.Constant(value, typeof(_003C_003Ec__DisplayClass54_1)), FieldInfo.GetFieldFromHandle((RuntimeFieldHandle)/*OpCode not supported: LdMemberToken*/, typeof(_003C_003Ec__DisplayClass54_1).TypeHandle)))), new ParameterExpression[1]
            //    {
            //        parameterExpression
            //    })));
            //    if (val2 != null)
            //    {
            //        this._userRoles.Remove(val2);
            //    }
            //}
        }

        public virtual async Task<IList<string>> GetRolesAsync(TUser user)
        {
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            TKey userId = ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Id;
            return await TaskExtensions.WithCurrentCulture<List<string>>(QueryableExtensions.ToListAsync<string>(Queryable.Join<TUserRole, TRole, TKey, string>(Queryable.Where<TUserRole>((IQueryable<TUserRole>)this._userRoles, (Expression<Func<TUserRole, bool>>)((TUserRole userRole) => ((IEquatable<TKey>)((IdentityUserRole<TKey>)userRole).UserId).Equals(userId))), (IEnumerable<TRole>)this._roleStore.DbEntitySet, (Expression<Func<TUserRole, TKey>>)((TUserRole userRole) => ((IdentityUserRole<TKey>)userRole).RoleId), (Expression<Func<TRole, TKey>>)((TRole role) => ((IdentityRole<TKey, TUserRole>)role).Id), (Expression<Func<TUserRole, TRole, string>>)((TUserRole userRole, TRole role) => ((IdentityRole<TKey, TUserRole>)role).Name))));
        }

        public virtual async Task<bool> IsInRoleAsync(TUser user, string roleName)
        {
            throw new NotImplementedException("LdMemberToken");
            //this.ThrowIfDisposed();
            //if (user == null)
            //{
            //    throw new ArgumentNullException("user");
            //}
            //if (string.IsNullOrWhiteSpace(roleName))
            //{
            //    throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, "roleName");
            //}
            //TRole val = await TaskExtensions.WithCurrentCulture<TRole>(QueryableExtensions.SingleOrDefaultAsync<TRole>((IQueryable<TRole>)this._roleStore.DbEntitySet, (Expression<Func<TRole, bool>>)((TRole r) => ((IdentityRole<TKey, TUserRole>)r).Name.ToUpper() == roleName.ToUpper())));
            //if (val != null)
            //{
            //    TKey userId = ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Id;
            //    TKey roleId = ((IdentityRole<TKey, TUserRole>)val).Id;
            //    IDbSet<TUserRole> userRoles = this._userRoles;
            //    ParameterExpression parameterExpression = Expression.Parameter(typeof(TUserRole), "ur");
            //    _003C_003Ec__DisplayClass56_1 value;
            //    return await TaskExtensions.WithCurrentCulture<bool>(QueryableExtensions.AnyAsync<TUserRole>((IQueryable<TUserRole>)userRoles, Expression.Lambda<Func<TUserRole, bool>>((Expression)Expression.AndAlso(Expression.Call(Expression.Property(parameterExpression, (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IdentityUserRole<TKey>).TypeHandle)), (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IEquatable<TKey>).TypeHandle), Expression.Field(Expression.Constant(value, typeof(_003C_003Ec__DisplayClass56_1)), FieldInfo.GetFieldFromHandle((RuntimeFieldHandle)/*OpCode not supported: LdMemberToken*/, typeof(_003C_003Ec__DisplayClass56_1).TypeHandle))), Expression.Call(Expression.Property(parameterExpression, (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IdentityUserRole<TKey>).TypeHandle)), (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IEquatable<TKey>).TypeHandle), Expression.Field(Expression.Constant(value, typeof(_003C_003Ec__DisplayClass56_1)), FieldInfo.GetFieldFromHandle((RuntimeFieldHandle)/*OpCode not supported: LdMemberToken*/, typeof(_003C_003Ec__DisplayClass56_1).TypeHandle)))), new ParameterExpression[1]
            //    {
            //        parameterExpression
            //    })));
            //}
            //return false;
        }

        public virtual Task SetSecurityStampAsync(TUser user, string stamp)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.SecurityStamp = stamp;
            return Task.FromResult<int>(0);
        }

        public virtual Task<string> GetSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult<string>(user.SecurityStamp);
        }

        public virtual Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.TwoFactorEnabled = enabled;
            return Task.FromResult<int>(0);
        }

        public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult<bool>(user.TwoFactorEnabled);
        }

        private async Task SaveChanges()
        {
            if (this.AutoSaveChanges)
            {
                await TaskExtensions.WithCurrentCulture<int>(this.Context.SaveChangesAsync());
            }
        }

        private bool AreClaimsLoaded(TUser user)
        {
            return Context.Entry<TUser>(user).Collection((TUser u) => u.Claims).IsLoaded;
        }

        private async Task EnsureClaimsLoaded(TUser user)
        {
            if (!this.AreClaimsLoaded(user))
            {
                TKey userId = ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Id;
                await Queryable.Where<TUserClaim>((IQueryable<TUserClaim>)this._userClaims, (Expression<Func<TUserClaim, bool>>)((TUserClaim uc) => ((IEquatable<TKey>)((IdentityUserClaim<TKey>)uc).UserId).Equals(userId))).LoadAsync().WithCurrentCulture();
                this.Context.Entry<TUser>(user).Collection((TUser u) => ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)u).Claims).IsLoaded = true;
            }
        }

        private async Task EnsureRolesLoaded(TUser user)
        {
            if (!this.Context.Entry<TUser>(user).Collection((TUser u) => ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)u).Roles).IsLoaded)
            {
                TKey userId = ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Id;
                await Queryable.Where<TUserRole>((IQueryable<TUserRole>)this._userRoles, (Expression<Func<TUserRole, bool>>)((TUserRole uc) => ((IEquatable<TKey>)((IdentityUserRole<TKey>)uc).UserId).Equals(userId))).LoadAsync().WithCurrentCulture();
                this.Context.Entry<TUser>(user).Collection((TUser u) => ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)u).Roles).IsLoaded = true;
            }
        }

        private bool AreLoginsLoaded(TUser user)
        {
            return Context.Entry<TUser>(user).Collection((TUser u) => u.Logins).IsLoaded;
        }

        private async Task EnsureLoginsLoaded(TUser user)
        {
            if (!this.AreLoginsLoaded(user))
            {
                TKey userId = ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)user).Id;
                await Queryable.Where<TUserLogin>((IQueryable<TUserLogin>)this._logins, (Expression<Func<TUserLogin, bool>>)((TUserLogin uc) => ((IEquatable<TKey>)((IdentityUserLogin<TKey>)uc).UserId).Equals(userId))).LoadAsync().WithCurrentCulture();
                this.Context.Entry<TUser>(user).Collection((TUser u) => ((IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>)u).Logins).IsLoaded = true;
            }
        }

        protected virtual async Task<TUser> GetUserAggregateAsync(Expression<Func<TUser, bool>> filter)
        {
            TKey id;
            TUser user = (!FindByIdFilterParser.TryMatchAndGetId(filter, out id)) ? (await TaskExtensions.WithCurrentCulture<TUser>(QueryableExtensions.FirstOrDefaultAsync<TUser>(this.Users, filter))) : (await TaskExtensions.WithCurrentCulture<TUser>(this._userStore.GetByIdAsync((object)id)));
            if (user != null)
            {
                await this.EnsureClaimsLoaded(user).WithCurrentCulture();
                await this.EnsureLoginsLoaded(user).WithCurrentCulture();
                await this.EnsureRolesLoaded(user).WithCurrentCulture();
            }
            return user;
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
            _userStore = null;
        }
    }
}