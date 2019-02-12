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
    public class UserStore<TUser> : UserStore<TUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>, IUserStore<TUser>, IUserStore<TUser, string> where TUser : IdentityUser
    {
        public UserStore() : this(new IdentityDbContext())
        {
            base.DisposeContext = true;
        }

        /// <summary>Constructor that takes the db context</summary>
        public UserStore(DbContext context) : base(context)
        {
        }
    }

    public class UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim> : IUserLoginStore<TUser, TKey>, IUserStore<TUser, TKey>, IDisposable, IUserClaimStore<TUser, TKey>, IUserRoleStore<TUser, TKey>, IUserPasswordStore<TUser, TKey>, IUserSecurityStampStore<TUser, TKey>, IQueryableUserStore<TUser, TKey>, IUserEmailStore<TUser, TKey>, IUserPhoneNumberStore<TUser, TKey>, IUserTwoFactorStore<TUser, TKey>, IUserLockoutStore<TUser, TKey> where TUser : IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim> where TRole : IdentityRole<TKey, TUserRole> where TKey : IEquatable<TKey> where TUserLogin : IdentityUserLogin<TKey>, new() where TUserRole : IdentityUserRole<TKey>, new() where TUserClaim : IdentityUserClaim<TKey>, new()
    {
        private static class FindByIdFilterParser
        {
            private static readonly Expression<Func<TUser, bool>> Predicate = u => u.Id.Equals(default(TKey));

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
            Context = context ?? throw new ArgumentNullException("context");
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
            return Enumerable.ToList(Enumerable.Select((user).Claims, (c => new Claim(c.ClaimType, c.ClaimValue))));
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
            TUserClaim val = new TUserClaim
            {
                UserId = user.Id,
                ClaimType = claim.Type,
                ClaimValue = claim.Value
            };
            userClaims.Add(val);
            return Task.FromResult(0);
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
                enumerable = Enumerable.ToList(Enumerable.Where(user.Claims, delegate (TUserClaim uc)
                {
                    if (uc.ClaimValue == claimValue)
                    {
                        return uc.ClaimType == claimType;
                    }
                    return false;
                }));
            }
            else
            {
                TKey userId = (user).Id;
                enumerable = await TaskExtensions.WithCurrentCulture(QueryableExtensions.ToListAsync(Queryable.Where(this._userClaims, (uc => uc.ClaimValue == claimValue && uc.ClaimType == claimType && uc.UserId.Equals(userId)))));
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
            return Task.FromResult(user.EmailConfirmed);
        }

        public virtual Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.EmailConfirmed = confirmed;
            return Task.FromResult(0);
        }

        public virtual Task SetEmailAsync(TUser user, string email)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.Email = email;
            return Task.FromResult(0);
        }

        public virtual Task<string> GetEmailAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.Email);
        }

        public virtual Task<TUser> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();
            return GetUserAggregateAsync(u => u.Email.ToUpper() == email.ToUpper());
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
            return Task.FromResult(0);
        }

        public virtual Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        public virtual Task ResetAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        public virtual Task<int> GetAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.AccessFailedCount);
        }

        public virtual Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.LockoutEnabled);
        }

        public virtual Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.LockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        public virtual Task<TUser> FindByIdAsync(TKey userId)
        {
            ThrowIfDisposed();
            return GetUserAggregateAsync(u => u.Id.Equals(userId));
        }

        public virtual Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();
            return GetUserAggregateAsync(u => u.UserName.ToUpper() == userName.ToUpper());
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
            //throw new NotImplementedException("LdMemberToken");
            this.ThrowIfDisposed();
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }
            string provider = login.LoginProvider;
            string key = login.ProviderKey;

            TUserLogin val = await this._logins.FirstOrDefaultAsync(l => l.LoginProvider.Equals(provider) && l.ProviderKey.Equals(key));
            //TUserLogin val = await TaskExtensions.WithCurrentCulture<TUserLogin>(QueryableExtensions.FirstOrDefaultAsync<TUserLogin>((IQueryable<TUserLogin>)this._logins, ((TUserLogin l) => l.LoginProvider == provider && l.ProviderKey == key)));
            if (val != null)
            {
                TKey userId = val.UserId;
                return await this._userStore.DbEntitySet.FirstOrDefaultAsync(m => m.Id.Equals(userId));

                //ParameterExpression parameterExpression = Expression.Parameter(typeof(TUser), "u");
                //_003C_003Ec__DisplayClass42_1 value;
                //return await TaskExtensions.WithCurrentCulture<TUser>(this.GetUserAggregateAsync(Expression.Lambda<Func<TUser, bool>>((Expression)Expression.Call(Expression.Property(parameterExpression, (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof.TypeHandle)), (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IEquatable<TKey>).TypeHandle), Expression.Field(Expression.Constant(value, typeof(_003C_003Ec__DisplayClass42_1)), FieldInfo.GetFieldFromHandle((RuntimeFieldHandle)/*OpCode not supported: LdMemberToken*/, typeof(_003C_003Ec__DisplayClass42_1).TypeHandle))), new ParameterExpression[1]
                //{
                //    parameterExpression
                //})));
            }
            return null;
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
            TUserLogin val = new TUserLogin
            {
                UserId = user.Id,
                ProviderKey = login.ProviderKey,
                LoginProvider = login.LoginProvider
            };
            logins.Add(val);
            return Task.FromResult(0);
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
                val = Enumerable.SingleOrDefault(user.Logins, delegate (TUserLogin ul)
                {
                    if (ul.LoginProvider == provider)
                    {
                        return ul.ProviderKey == key;
                    }
                    return false;
                });
            }
            else
            {
                TKey userId = user.Id;
                val = await TaskExtensions.WithCurrentCulture(QueryableExtensions.SingleOrDefaultAsync(this._logins, (ul => ul.LoginProvider == provider && ul.ProviderKey == key && (ul.UserId).Equals(userId))));
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
            return Enumerable.ToList(Enumerable.Select(user.Logins, (l => new UserLoginInfo(l.LoginProvider, l.ProviderKey))));
        }

        public virtual Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        public virtual Task<string> GetPasswordHashAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.PasswordHash);
        }

        public virtual Task<bool> HasPasswordAsync(TUser user)
        {
            return Task.FromResult(user.PasswordHash != null);
        }

        public virtual Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        public virtual Task<string> GetPhoneNumberAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.PhoneNumber);
        }

        public virtual Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public virtual Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.PhoneNumberConfirmed = confirmed;
            return Task.FromResult(0);
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
            TRole val = await TaskExtensions.WithCurrentCulture(QueryableExtensions.SingleOrDefaultAsync(this._roleStore.DbEntitySet, r => r.Name.ToUpper() == roleName.ToUpper()));
            if (val == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, IdentityResources.RoleNotFound, new object[1]
                {
                    roleName
                }));
            }
            TUserRole val2 = new TUserRole
            {
                UserId = user.Id,
                RoleId = val.Id
            };
            TUserRole entity = val2;
            this._userRoles.Add(entity);
        }

        public virtual async Task RemoveFromRoleAsync(TUser user, string roleName)
        {
            //throw new NotImplementedException("LdMemberToken");
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, "roleName");
            }

            TRole val = await this._roleStore.DbEntitySet.SingleOrDefaultAsync(r => r.Name.ToUpper().Equals(roleName.ToUpper()));
            //TRole val = await TaskExtensions.WithCurrentCulture<TRole>(QueryableExtensions.SingleOrDefaultAsync<TRole>((IQueryable<TRole>)this._roleStore.DbEntitySet, (Expression<Func<TRole, bool>>)((TRole r) => ((IdentityRole<TKey, TUserRole>)r).Name.ToUpper() == roleName.ToUpper())));
            if (val != null)
            {
                TKey roleId = val.Id;
                TKey userId = user.Id;
                IDbSet<TUserRole> userRoles = this._userRoles;

                TUserRole val2 = await userRoles.FirstOrDefaultAsync(m => m.RoleId.Equals(roleId) && m.UserId.Equals(userId));
                //    ParameterExpression parameterExpression = Expression.Parameter(typeof(TUserRole), "r");
                //    _003C_003Ec__DisplayClass54_1 value;
                //    TUserRole val2 = await TaskExtensions.WithCurrentCulture<TUserRole>(QueryableExtensions.FirstOrDefaultAsync<TUserRole>((IQueryable<TUserRole>)userRoles, Expression.Lambda<Func<TUserRole, bool>>((Expression)Expression.AndAlso(Expression.Call(Expression.Field(Expression.Constant(value, typeof(_003C_003Ec__DisplayClass54_1)), FieldInfo.GetFieldFromHandle((RuntimeFieldHandle)/*OpCode not supported: LdMemberToken*/, typeof(_003C_003Ec__DisplayClass54_1).TypeHandle)), (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IEquatable<TKey>).TypeHandle), Expression.Property(parameterExpression, (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IdentityUserRole<TKey>).TypeHandle))), Expression.Call(Expression.Property(parameterExpression, (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IdentityUserRole<TKey>).TypeHandle)), (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IEquatable<TKey>).TypeHandle), Expression.Field(Expression.Constant(value, typeof(_003C_003Ec__DisplayClass54_1)), FieldInfo.GetFieldFromHandle((RuntimeFieldHandle)/*OpCode not supported: LdMemberToken*/, typeof(_003C_003Ec__DisplayClass54_1).TypeHandle)))), new ParameterExpression[1]
                //    {
                //        parameterExpression
                //    })));
                if (val2 != null)
                {
                    this._userRoles.Remove(val2);
                }
            }
        }

        public virtual async Task<IList<string>> GetRolesAsync(TUser user)
        {
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            TKey userId = (user).Id;
            return await TaskExtensions.WithCurrentCulture(QueryableExtensions.ToListAsync(Queryable.Join(Queryable.Where(this._userRoles, (userRole => (userRole.UserId).Equals(userId))), this._roleStore.DbEntitySet, (userRole => userRole.RoleId), (role => role.Id), ((userRole, role) => role.Name))));
        }

        public virtual async Task<bool> IsInRoleAsync(TUser user, string roleName)
        {
            //throw new NotImplementedException("LdMemberToken");
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, "roleName");
            }
            //TRole val = await TaskExtensions.WithCurrentCulture<TRole>(QueryableExtensions.SingleOrDefaultAsync<TRole>((IQueryable<TRole>)this._roleStore.DbEntitySet, (Expression<Func<TRole, bool>>)((TRole r) => ((IdentityRole<TKey, TUserRole>)r).Name.ToUpper() == roleName.ToUpper())));
            TRole val = await this._roleStore.DbEntitySet.SingleOrDefaultAsync(r => r.Name.ToUpper().Equals(roleName.ToUpper()));
            if (val != null)
            {
                TKey userId = user.Id;
                TKey roleId = val.Id;
                IDbSet<TUserRole> userRoles = this._userRoles;

                return await userRoles.AnyAsync(m => m.RoleId.Equals(roleId) && m.UserId.Equals(userId));

                //    ParameterExpression parameterExpression = Expression.Parameter(typeof(TUserRole), "ur");
                //    _003C_003Ec__DisplayClass56_1 value;
                //    return await TaskExtensions.WithCurrentCulture<bool>(QueryableExtensions.AnyAsync<TUserRole>((IQueryable<TUserRole>)userRoles, Expression.Lambda<Func<TUserRole, bool>>((Expression)Expression.AndAlso(Expression.Call(Expression.Property(parameterExpression, (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IdentityUserRole<TKey>).TypeHandle)), (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IEquatable<TKey>).TypeHandle), Expression.Field(Expression.Constant(value, typeof(_003C_003Ec__DisplayClass56_1)), FieldInfo.GetFieldFromHandle((RuntimeFieldHandle)/*OpCode not supported: LdMemberToken*/, typeof(_003C_003Ec__DisplayClass56_1).TypeHandle))), Expression.Call(Expression.Property(parameterExpression, (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IdentityUserRole<TKey>).TypeHandle)), (MethodInfo)MethodBase.GetMethodFromHandle((RuntimeMethodHandle)/*OpCode not supported: LdMemberToken*/, typeof(IEquatable<TKey>).TypeHandle), Expression.Field(Expression.Constant(value, typeof(_003C_003Ec__DisplayClass56_1)), FieldInfo.GetFieldFromHandle((RuntimeFieldHandle)/*OpCode not supported: LdMemberToken*/, typeof(_003C_003Ec__DisplayClass56_1).TypeHandle)))), new ParameterExpression[1]
                //    {
                //        parameterExpression
                //    })));
            }
            return false;
        }

        public virtual Task SetSecurityStampAsync(TUser user, string stamp)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }

        public virtual Task<string> GetSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.SecurityStamp);
        }

        public virtual Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.TwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.TwoFactorEnabled);
        }

        private async Task SaveChanges()
        {
            if (this.AutoSaveChanges)
            {
                await TaskExtensions.WithCurrentCulture(this.Context.SaveChangesAsync());
            }
        }

        private bool AreClaimsLoaded(TUser user)
        {
            return Context.Entry(user).Collection(u => u.Claims).IsLoaded;
        }

        private async Task EnsureClaimsLoaded(TUser user)
        {
            if (!this.AreClaimsLoaded(user))
            {
                TKey userId = (user).Id;

                await this._userClaims.Where(m => m.UserId.Equals(userId)).LoadAsync().WithCurrentCulture();
                //await Queryable.Where<TUserClaim>((IQueryable<TUserClaim>)this._userClaims, (Expression<Func<TUserClaim, bool>>)((TUserClaim uc) => ((IEquatable<TKey>)((IdentityUserClaim<TKey>)uc).UserId).Equals(userId))).LoadAsync().WithCurrentCulture();
                this.Context.Entry(user).Collection(u => u.Claims).IsLoaded = true;
            }
        }

        private async Task EnsureRolesLoaded(TUser user)
        {
            if (!this.Context.Entry(user).Collection(u => u.Roles).IsLoaded)
            {
                TKey userId = (user).Id;
                await this._userRoles.Where(m => m.UserId.Equals(userId)).LoadAsync().WithCurrentCulture();
                //await Queryable.Where<TUserRole>((IQueryable<TUserRole>)this._userRoles, (Expression<Func<TUserRole, bool>>)((TUserRole uc) => ((IEquatable<TKey>)((IdentityUserRole<TKey>)uc).UserId).Equals(userId))).LoadAsync().WithCurrentCulture();
                this.Context.Entry(user).Collection(u => u.Roles).IsLoaded = true;
            }
        }

        private bool AreLoginsLoaded(TUser user)
        {
            return Context.Entry(user).Collection(u => u.Logins).IsLoaded;
        }

        private async Task EnsureLoginsLoaded(TUser user)
        {
            if (!this.AreLoginsLoaded(user))
            {
                TKey userId = (user).Id;
                await this._logins.Where(m => m.UserId.Equals(userId)).LoadAsync().WithCurrentCulture();
                //await Queryable.Where<TUserLogin>((IQueryable<TUserLogin>)this._logins, ((TUserLogin uc) => ((IEquatable<TKey>)uc.UserId).Equals(userId))).LoadAsync().WithCurrentCulture();
                this.Context.Entry(user).Collection(u => u.Logins).IsLoaded = true;
            }
        }

        protected virtual async Task<TUser> GetUserAggregateAsync(Expression<Func<TUser, bool>> filter)
        {
            TUser user = (!FindByIdFilterParser.TryMatchAndGetId(filter, out TKey id)) ? (await TaskExtensions.WithCurrentCulture(QueryableExtensions.FirstOrDefaultAsync(this.Users, filter))) : (await TaskExtensions.WithCurrentCulture(this._userStore.GetByIdAsync(id)));
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