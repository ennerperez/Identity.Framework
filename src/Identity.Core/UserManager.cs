using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     UserManager for users where the primary key for the User is of type string
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	public class UserManager<TUser> : UserManager<TUser, string> where TUser : class, IUser<string>
	{
		/// <summary>
		///     Constructor
		/// </summary>
		/// <param name="store"></param>
		public UserManager(IUserStore<TUser> store)
			: base((IUserStore<TUser, string>)store)
		{
		}
	}
	/// <summary>
	///     Exposes user related api which will automatically save changes to the UserStore
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	/// <typeparam name="TKey"></typeparam>
	public class UserManager<TUser, TKey> : IDisposable where TUser : class, IUser<TKey> where TKey : IEquatable<TKey>
	{
		private readonly Dictionary<string, IUserTokenProvider<TUser, TKey>> _factors = new Dictionary<string, IUserTokenProvider<TUser, TKey>>();

		private IClaimsIdentityFactory<TUser, TKey> _claimsFactory;

		private TimeSpan _defaultLockout = TimeSpan.Zero;

		private bool _disposed;

		private IPasswordHasher _passwordHasher;

		private IIdentityValidator<string> _passwordValidator;

		private IIdentityValidator<TUser> _userValidator;

		/// <summary>
		///     Persistence abstraction that the UserManager operates against
		/// </summary>
		protected internal IUserStore<TUser, TKey> Store
		{
			get;
			set;
		}

		/// <summary>
		///     Used to hash/verify passwords
		/// </summary>
		public IPasswordHasher PasswordHasher
		{
			get
			{
				ThrowIfDisposed();
				return _passwordHasher;
			}
			set
			{
				ThrowIfDisposed();
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				_passwordHasher = value;
			}
		}

		/// <summary>
		///     Used to validate users before changes are saved
		/// </summary>
		public IIdentityValidator<TUser> UserValidator
		{
			get
			{
				ThrowIfDisposed();
				return _userValidator;
			}
			set
			{
				ThrowIfDisposed();
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				_userValidator = value;
			}
		}

		/// <summary>
		///     Used to validate passwords before persisting changes
		/// </summary>
		public IIdentityValidator<string> PasswordValidator
		{
			get
			{
				ThrowIfDisposed();
				return _passwordValidator;
			}
			set
			{
				ThrowIfDisposed();
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				_passwordValidator = value;
			}
		}

		/// <summary>
		///     Used to create claims identities from users
		/// </summary>
		public IClaimsIdentityFactory<TUser, TKey> ClaimsIdentityFactory
		{
			get
			{
				ThrowIfDisposed();
				return _claimsFactory;
			}
			set
			{
				ThrowIfDisposed();
				if (value == null)
				{
					throw new ArgumentNullException("value");
				}
				_claimsFactory = value;
			}
		}

		/// <summary>
		///     Used to send email
		/// </summary>
		public IIdentityMessageService EmailService
		{
			get;
			set;
		}

		/// <summary>
		///     Used to send a sms message
		/// </summary>
		public IIdentityMessageService SmsService
		{
			get;
			set;
		}

		/// <summary>
		///     Used for generating reset password and confirmation tokens
		/// </summary>
		public IUserTokenProvider<TUser, TKey> UserTokenProvider
		{
			get;
			set;
		}

		/// <summary>
		///     If true, will enable user lockout when users are created
		/// </summary>
		public bool UserLockoutEnabledByDefault
		{
			get;
			set;
		}

		/// <summary>
		///     Number of access attempts allowed before a user is locked out (if lockout is enabled)
		/// </summary>
		public int MaxFailedAccessAttemptsBeforeLockout
		{
			get;
			set;
		}

		/// <summary>
		///     Default amount of time that a user is locked out for after MaxFailedAccessAttemptsBeforeLockout is reached
		/// </summary>
		public TimeSpan DefaultAccountLockoutTimeSpan
		{
			get
			{
				return _defaultLockout;
			}
			set
			{
				_defaultLockout = value;
			}
		}

		/// <summary>
		///     Returns true if the store is an IUserTwoFactorStore
		/// </summary>
		public virtual bool SupportsUserTwoFactor
		{
			get
			{
				ThrowIfDisposed();
				return Store is IUserTwoFactorStore<TUser, TKey>;
			}
		}

		/// <summary>
		///     Returns true if the store is an IUserPasswordStore
		/// </summary>
		public virtual bool SupportsUserPassword
		{
			get
			{
				ThrowIfDisposed();
				return Store is IUserPasswordStore<TUser, TKey>;
			}
		}

		/// <summary>
		///     Returns true if the store is an IUserSecurityStore
		/// </summary>
		public virtual bool SupportsUserSecurityStamp
		{
			get
			{
				ThrowIfDisposed();
				return Store is IUserSecurityStampStore<TUser, TKey>;
			}
		}

		/// <summary>
		///     Returns true if the store is an IUserRoleStore
		/// </summary>
		public virtual bool SupportsUserRole
		{
			get
			{
				ThrowIfDisposed();
				return Store is IUserRoleStore<TUser, TKey>;
			}
		}

		/// <summary>
		///     Returns true if the store is an IUserLoginStore
		/// </summary>
		public virtual bool SupportsUserLogin
		{
			get
			{
				ThrowIfDisposed();
				return Store is IUserLoginStore<TUser, TKey>;
			}
		}

		/// <summary>
		///     Returns true if the store is an IUserEmailStore
		/// </summary>
		public virtual bool SupportsUserEmail
		{
			get
			{
				ThrowIfDisposed();
				return Store is IUserEmailStore<TUser, TKey>;
			}
		}

		/// <summary>
		///     Returns true if the store is an IUserPhoneNumberStore
		/// </summary>
		public virtual bool SupportsUserPhoneNumber
		{
			get
			{
				ThrowIfDisposed();
				return Store is IUserPhoneNumberStore<TUser, TKey>;
			}
		}

		/// <summary>
		///     Returns true if the store is an IUserClaimStore
		/// </summary>
		public virtual bool SupportsUserClaim
		{
			get
			{
				ThrowIfDisposed();
				return Store is IUserClaimStore<TUser, TKey>;
			}
		}

		/// <summary>
		///     Returns true if the store is an IUserLockoutStore
		/// </summary>
		public virtual bool SupportsUserLockout
		{
			get
			{
				ThrowIfDisposed();
				return Store is IUserLockoutStore<TUser, TKey>;
			}
		}

		/// <summary>
		///     Returns true if the store is an IQueryableUserStore
		/// </summary>
		public virtual bool SupportsQueryableUsers
		{
			get
			{
				ThrowIfDisposed();
				return Store is IQueryableUserStore<TUser, TKey>;
			}
		}

		/// <summary>
		///     Returns an IQueryable of users if the store is an IQueryableUserStore
		/// </summary>
		public virtual IQueryable<TUser> Users
		{
			get
			{
				IQueryableUserStore<TUser, TKey> obj = Store as IQueryableUserStore<TUser, TKey>;
				if (obj == null)
				{
					throw new NotSupportedException(Resources.StoreNotIQueryableUserStore);
				}
				return obj.Users;
			}
		}

		/// <summary>
		/// Maps the registered two-factor authentication providers for users by their id
		/// </summary>
		public IDictionary<string, IUserTokenProvider<TUser, TKey>> TwoFactorProviders => _factors;

		/// <summary>
		///     Constructor
		/// </summary>
		/// <param name="store">The IUserStore is responsible for commiting changes via the UpdateAsync/CreateAsync methods</param>
		public UserManager(IUserStore<TUser, TKey> store)
		{
			if (store == null)
			{
				throw new ArgumentNullException("store");
			}
			Store = store;
			UserValidator = new UserValidator<TUser, TKey>(this);
			PasswordValidator = new MinimumLengthValidator(6);
			PasswordHasher = new PasswordHasher();
			ClaimsIdentityFactory = new ClaimsIdentityFactory<TUser, TKey>();
		}

		/// <summary>
		///     Dispose this object
		/// </summary>
		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		/// <summary>
		///     Creates a ClaimsIdentity representing the user
		/// </summary>
		/// <param name="user"></param>
		/// <param name="authenticationType"></param>
		/// <returns></returns>
		public virtual Task<ClaimsIdentity> CreateIdentityAsync(TUser user, string authenticationType)
		{
			ThrowIfDisposed();
			if (user == null)
			{
				throw new ArgumentNullException("user");
			}
			return ClaimsIdentityFactory.CreateAsync(this, user, authenticationType);
		}

		/// <summary>
		///     Create a user with no password
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> CreateAsync(TUser user)
		{
			this.ThrowIfDisposed();
			await this.UpdateSecurityStampInternal(user).WithCurrentCulture();
			IdentityResult identityResult = await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UserValidator.ValidateAsync(user));
			if (!identityResult.Succeeded)
			{
				return identityResult;
			}
			if (this.UserLockoutEnabledByDefault && this.SupportsUserLockout)
			{
				await this.GetUserLockoutStore().SetLockoutEnabledAsync(user, true).WithCurrentCulture();
			}
			await this.Store.CreateAsync(user).WithCurrentCulture();
			return IdentityResult.Success;
		}

		/// <summary>
		///     Update a user
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> UpdateAsync(TUser user)
		{
			this.ThrowIfDisposed();
			if (user == null)
			{
				throw new ArgumentNullException("user");
			}
			IdentityResult identityResult = await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UserValidator.ValidateAsync(user));
			if (!identityResult.Succeeded)
			{
				return identityResult;
			}
			await this.Store.UpdateAsync(user).WithCurrentCulture();
			return IdentityResult.Success;
		}

		/// <summary>
		///     Delete a user
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> DeleteAsync(TUser user)
		{
			this.ThrowIfDisposed();
			await this.Store.DeleteAsync(user).WithCurrentCulture();
			return IdentityResult.Success;
		}

		/// <summary>
		///     Find a user by id
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual Task<TUser> FindByIdAsync(TKey userId)
		{
			ThrowIfDisposed();
			return Store.FindByIdAsync(userId);
		}

		/// <summary>
		///     Find a user by user name
		/// </summary>
		/// <param name="userName"></param>
		/// <returns></returns>
		public virtual Task<TUser> FindByNameAsync(string userName)
		{
			ThrowIfDisposed();
			if (userName == null)
			{
				throw new ArgumentNullException("userName");
			}
			return Store.FindByNameAsync(userName);
		}

		private IUserPasswordStore<TUser, TKey> GetPasswordStore()
		{
			IUserPasswordStore<TUser, TKey> obj = Store as IUserPasswordStore<TUser, TKey>;
			if (obj == null)
			{
				throw new NotSupportedException(Resources.StoreNotIUserPasswordStore);
			}
			return obj;
		}

		/// <summary>
		///     Create a user with the given password
		/// </summary>
		/// <param name="user"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> CreateAsync(TUser user, string password)
		{
			this.ThrowIfDisposed();
			IUserPasswordStore<TUser, TKey> passwordStore = this.GetPasswordStore();
			if (user == null)
			{
				throw new ArgumentNullException("user");
			}
			if (password == null)
			{
				throw new ArgumentNullException("password");
			}
			IdentityResult identityResult = await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdatePassword(passwordStore, user, password));
			if (!identityResult.Succeeded)
			{
				return identityResult;
			}
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.CreateAsync(user));
		}

		/// <summary>
		///     Return a user with the specified username and password or null if there is no match.
		/// </summary>
		/// <param name="userName"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public virtual async Task<TUser> FindAsync(string userName, string password)
		{
			this.ThrowIfDisposed();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByNameAsync(userName));
			if (user == null)
			{
				return null;
			}
			return (await TaskExtensions.WithCurrentCulture<bool>(this.CheckPasswordAsync(user, password))) ? user : null;
		}

		/// <summary>
		///     Returns true if the password is valid for the user
		/// </summary>
		/// <param name="user"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public virtual async Task<bool> CheckPasswordAsync(TUser user, string password)
		{
			this.ThrowIfDisposed();
			IUserPasswordStore<TUser, TKey> passwordStore = this.GetPasswordStore();
			if (user == null)
			{
				return false;
			}
			return await TaskExtensions.WithCurrentCulture<bool>(this.VerifyPasswordAsync(passwordStore, user, password));
		}

		/// <summary>
		///     Returns true if the user has a password
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<bool> HasPasswordAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserPasswordStore<TUser, TKey> passwordStore = this.GetPasswordStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<bool>(passwordStore.HasPasswordAsync(val));
		}

		/// <summary>
		///     Add a user password only if one does not already exist
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> AddPasswordAsync(TKey userId, string password)
		{
			this.ThrowIfDisposed();
			IUserPasswordStore<TUser, TKey> passwordStore = this.GetPasswordStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (await TaskExtensions.WithCurrentCulture<string>(passwordStore.GetPasswordHashAsync(user)) != null)
			{
				return new IdentityResult(Resources.UserAlreadyHasPassword);
			}
			IdentityResult identityResult = await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdatePassword(passwordStore, user, password));
			if (!identityResult.Succeeded)
			{
				return identityResult;
			}
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Change a user password
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="currentPassword"></param>
		/// <param name="newPassword"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> ChangePasswordAsync(TKey userId, string currentPassword, string newPassword)
		{
			this.ThrowIfDisposed();
			IUserPasswordStore<TUser, TKey> passwordStore = this.GetPasswordStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (await TaskExtensions.WithCurrentCulture<bool>(this.VerifyPasswordAsync(passwordStore, user, currentPassword)))
			{
				IdentityResult identityResult = await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdatePassword(passwordStore, user, newPassword));
				if (!identityResult.Succeeded)
				{
					return identityResult;
				}
				return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
			}
			return IdentityResult.Failed(Resources.PasswordMismatch);
		}

		/// <summary>
		///     Remove a user's password
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> RemovePasswordAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserPasswordStore<TUser, TKey> passwordStore = this.GetPasswordStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			await passwordStore.SetPasswordHashAsync(user, (string)null).WithCurrentCulture();
			await this.UpdateSecurityStampInternal(user).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		protected virtual async Task<IdentityResult> UpdatePassword(IUserPasswordStore<TUser, TKey> passwordStore, TUser user, string newPassword)
		{
			IdentityResult identityResult = await TaskExtensions.WithCurrentCulture<IdentityResult>(this.PasswordValidator.ValidateAsync(newPassword));
			if (!identityResult.Succeeded)
			{
				return identityResult;
			}
			await passwordStore.SetPasswordHashAsync(user, this.PasswordHasher.HashPassword(newPassword)).WithCurrentCulture();
			await this.UpdateSecurityStampInternal(user).WithCurrentCulture();
			return IdentityResult.Success;
		}

		/// <summary>
		///     By default, retrieves the hashed password from the user store and calls PasswordHasher.VerifyHashPassword
		/// </summary>
		/// <param name="store"></param>
		/// <param name="user"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		protected virtual async Task<bool> VerifyPasswordAsync(IUserPasswordStore<TUser, TKey> store, TUser user, string password)
		{
			string hashedPassword = await TaskExtensions.WithCurrentCulture<string>(store.GetPasswordHashAsync(user));
			return this.PasswordHasher.VerifyHashedPassword(hashedPassword, password) != PasswordVerificationResult.Failed;
		}

		private IUserSecurityStampStore<TUser, TKey> GetSecurityStore()
		{
			IUserSecurityStampStore<TUser, TKey> obj = Store as IUserSecurityStampStore<TUser, TKey>;
			if (obj == null)
			{
				throw new NotSupportedException(Resources.StoreNotIUserSecurityStampStore);
			}
			return obj;
		}

		/// <summary>
		///     Returns the current security stamp for a user
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<string> GetSecurityStampAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserSecurityStampStore<TUser, TKey> securityStore = this.GetSecurityStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<string>(securityStore.GetSecurityStampAsync(val));
		}

		/// <summary>
		///     Generate a new security stamp for a user, used for SignOutEverywhere functionality
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> UpdateSecurityStampAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserSecurityStampStore<TUser, TKey> securityStore = this.GetSecurityStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			await securityStore.SetSecurityStampAsync(user, UserManager<TUser, TKey>.NewSecurityStamp()).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Generate a password reset token for the user using the UserTokenProvider
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual Task<string> GeneratePasswordResetTokenAsync(TKey userId)
		{
			ThrowIfDisposed();
			return GenerateUserTokenAsync("ResetPassword", userId);
		}

		/// <summary>
		///     Reset a user's password using a reset password token
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="token"></param>
		/// <param name="newPassword"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> ResetPasswordAsync(TKey userId, string token, string newPassword)
		{
			this.ThrowIfDisposed();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (!(await TaskExtensions.WithCurrentCulture<bool>(this.VerifyUserTokenAsync(userId, "ResetPassword", token))))
			{
				return IdentityResult.Failed(Resources.InvalidToken);
			}
			IUserPasswordStore<TUser, TKey> passwordStore = this.GetPasswordStore();
			IdentityResult identityResult = await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdatePassword(passwordStore, user, newPassword));
			if (!identityResult.Succeeded)
			{
				return identityResult;
			}
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		internal async Task UpdateSecurityStampInternal(TUser user)
		{
			if (this.SupportsUserSecurityStamp)
			{
				await this.GetSecurityStore().SetSecurityStampAsync(user, UserManager<TUser, TKey>.NewSecurityStamp()).WithCurrentCulture();
			}
		}

		private static string NewSecurityStamp()
		{
			return Guid.NewGuid().ToString();
		}

		private IUserLoginStore<TUser, TKey> GetLoginStore()
		{
			IUserLoginStore<TUser, TKey> obj = Store as IUserLoginStore<TUser, TKey>;
			if (obj == null)
			{
				throw new NotSupportedException(Resources.StoreNotIUserLoginStore);
			}
			return obj;
		}

		/// <summary>
		///     Returns the user associated with this login
		/// </summary>
		/// <returns></returns>
		public virtual Task<TUser> FindAsync(UserLoginInfo login)
		{
			ThrowIfDisposed();
			return GetLoginStore().FindAsync(login);
		}

		/// <summary>
		///     Remove a user login
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="login"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> RemoveLoginAsync(TKey userId, UserLoginInfo login)
		{
			this.ThrowIfDisposed();
			IUserLoginStore<TUser, TKey> loginStore = this.GetLoginStore();
			if (login == null)
			{
				throw new ArgumentNullException("login");
			}
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			await loginStore.RemoveLoginAsync(user, login).WithCurrentCulture();
			await this.UpdateSecurityStampInternal(user).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Associate a login with a user
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="login"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> AddLoginAsync(TKey userId, UserLoginInfo login)
		{
			this.ThrowIfDisposed();
			IUserLoginStore<TUser, TKey> loginStore = this.GetLoginStore();
			if (login == null)
			{
				throw new ArgumentNullException("login");
			}
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (await TaskExtensions.WithCurrentCulture<TUser>(this.FindAsync(login)) != null)
			{
				return IdentityResult.Failed(Resources.ExternalLoginExists);
			}
			await loginStore.AddLoginAsync(user, login).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Gets the logins for a user.
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<IList<UserLoginInfo>> GetLoginsAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserLoginStore<TUser, TKey> loginStore = this.GetLoginStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<IList<UserLoginInfo>>(loginStore.GetLoginsAsync(val));
		}

		private IUserClaimStore<TUser, TKey> GetClaimStore()
		{
			IUserClaimStore<TUser, TKey> obj = Store as IUserClaimStore<TUser, TKey>;
			if (obj == null)
			{
				throw new NotSupportedException(Resources.StoreNotIUserClaimStore);
			}
			return obj;
		}

		/// <summary>
		///     Add a user claim
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="claim"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> AddClaimAsync(TKey userId, Claim claim)
		{
			this.ThrowIfDisposed();
			IUserClaimStore<TUser, TKey> claimStore = this.GetClaimStore();
			if (claim == null)
			{
				throw new ArgumentNullException("claim");
			}
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			await claimStore.AddClaimAsync(user, claim).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Remove a user claim
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="claim"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> RemoveClaimAsync(TKey userId, Claim claim)
		{
			this.ThrowIfDisposed();
			IUserClaimStore<TUser, TKey> claimStore = this.GetClaimStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			await claimStore.RemoveClaimAsync(user, claim).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Get a users's claims
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<IList<Claim>> GetClaimsAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserClaimStore<TUser, TKey> claimStore = this.GetClaimStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<IList<Claim>>(claimStore.GetClaimsAsync(val));
		}

		private IUserRoleStore<TUser, TKey> GetUserRoleStore()
		{
			IUserRoleStore<TUser, TKey> obj = Store as IUserRoleStore<TUser, TKey>;
			if (obj == null)
			{
				throw new NotSupportedException(Resources.StoreNotIUserRoleStore);
			}
			return obj;
		}

		/// <summary>
		///     Add a user to a role
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="role"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> AddToRoleAsync(TKey userId, string role)
		{
			this.ThrowIfDisposed();
			IUserRoleStore<TUser, TKey> userRoleStore = this.GetUserRoleStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (((ICollection<string>)(await TaskExtensions.WithCurrentCulture<IList<string>>(userRoleStore.GetRolesAsync(user)))).Contains(role))
			{
				return new IdentityResult(Resources.UserAlreadyInRole);
			}
			await userRoleStore.AddToRoleAsync(user, role).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		/// Method to add user to multiple roles
		/// </summary>
		/// <param name="userId">user id</param>
		/// <param name="roles">list of role names</param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> AddToRolesAsync(TKey userId, params string[] roles)
		{
			this.ThrowIfDisposed();
			IUserRoleStore<TUser, TKey> userRoleStore = this.GetUserRoleStore();
			if (roles == null)
			{
				throw new ArgumentNullException("roles");
			}
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			IList<string> userRoles = await TaskExtensions.WithCurrentCulture<IList<string>>(userRoleStore.GetRolesAsync(user));
			foreach (string text in roles)
			{
				if (((ICollection<string>)userRoles).Contains(text))
				{
					return new IdentityResult(Resources.UserAlreadyInRole);
				}
				await userRoleStore.AddToRoleAsync(user, text).WithCurrentCulture();
			}
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		/// Remove user from multiple roles
		/// </summary>
		/// <param name="userId">user id</param>
		/// <param name="roles">list of role names</param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> RemoveFromRolesAsync(TKey userId, params string[] roles)
		{
			this.ThrowIfDisposed();
			IUserRoleStore<TUser, TKey> userRoleStore = this.GetUserRoleStore();
			if (roles == null)
			{
				throw new ArgumentNullException("roles");
			}
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			IList<string> userRoles = await TaskExtensions.WithCurrentCulture<IList<string>>(userRoleStore.GetRolesAsync(user));
			foreach (string text in roles)
			{
				if (!((ICollection<string>)userRoles).Contains(text))
				{
					return new IdentityResult(Resources.UserNotInRole);
				}
				await userRoleStore.RemoveFromRoleAsync(user, text).WithCurrentCulture();
			}
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Remove a user from a role.
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="role"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> RemoveFromRoleAsync(TKey userId, string role)
		{
			this.ThrowIfDisposed();
			IUserRoleStore<TUser, TKey> userRoleStore = this.GetUserRoleStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (!(await TaskExtensions.WithCurrentCulture<bool>(userRoleStore.IsInRoleAsync(user, role))))
			{
				return new IdentityResult(Resources.UserNotInRole);
			}
			await userRoleStore.RemoveFromRoleAsync(user, role).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Returns the roles for the user
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<IList<string>> GetRolesAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserRoleStore<TUser, TKey> userRoleStore = this.GetUserRoleStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<IList<string>>(userRoleStore.GetRolesAsync(val));
		}

		/// <summary>
		///     Returns true if the user is in the specified role
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="role"></param>
		/// <returns></returns>
		public virtual async Task<bool> IsInRoleAsync(TKey userId, string role)
		{
			this.ThrowIfDisposed();
			IUserRoleStore<TUser, TKey> userRoleStore = this.GetUserRoleStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<bool>(userRoleStore.IsInRoleAsync(val, role));
		}

		internal IUserEmailStore<TUser, TKey> GetEmailStore()
		{
			IUserEmailStore<TUser, TKey> obj = Store as IUserEmailStore<TUser, TKey>;
			if (obj == null)
			{
				throw new NotSupportedException(Resources.StoreNotIUserEmailStore);
			}
			return obj;
		}

		/// <summary>
		///     Get a user's email
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<string> GetEmailAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserEmailStore<TUser, TKey> store = this.GetEmailStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<string>(store.GetEmailAsync(val));
		}

		/// <summary>
		///     Set a user's email
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="email"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> SetEmailAsync(TKey userId, string email)
		{
			this.ThrowIfDisposed();
			IUserEmailStore<TUser, TKey> store = this.GetEmailStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			await store.SetEmailAsync(user, email).WithCurrentCulture();
			await store.SetEmailConfirmedAsync(user, false).WithCurrentCulture();
			await this.UpdateSecurityStampInternal(user).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Find a user by his email
		/// </summary>
		/// <param name="email"></param>
		/// <returns></returns>
		public virtual Task<TUser> FindByEmailAsync(string email)
		{
			ThrowIfDisposed();
			IUserEmailStore<TUser, TKey> emailStore = GetEmailStore();
			if (email == null)
			{
				throw new ArgumentNullException("email");
			}
			return emailStore.FindByEmailAsync(email);
		}

		/// <summary>
		///     Get the email confirmation token for the user
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual Task<string> GenerateEmailConfirmationTokenAsync(TKey userId)
		{
			ThrowIfDisposed();
			return GenerateUserTokenAsync("Confirmation", userId);
		}

		/// <summary>
		///     Confirm the user's email with confirmation token
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="token"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> ConfirmEmailAsync(TKey userId, string token)
		{
			this.ThrowIfDisposed();
			IUserEmailStore<TUser, TKey> store = this.GetEmailStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (!(await TaskExtensions.WithCurrentCulture<bool>(this.VerifyUserTokenAsync(userId, "Confirmation", token))))
			{
				return IdentityResult.Failed(Resources.InvalidToken);
			}
			await store.SetEmailConfirmedAsync(user, true).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Returns true if the user's email has been confirmed
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<bool> IsEmailConfirmedAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserEmailStore<TUser, TKey> store = this.GetEmailStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<bool>(store.GetEmailConfirmedAsync(val));
		}

		internal IUserPhoneNumberStore<TUser, TKey> GetPhoneNumberStore()
		{
			IUserPhoneNumberStore<TUser, TKey> obj = Store as IUserPhoneNumberStore<TUser, TKey>;
			if (obj == null)
			{
				throw new NotSupportedException(Resources.StoreNotIUserPhoneNumberStore);
			}
			return obj;
		}

		/// <summary>
		///     Get a user's phoneNumber
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<string> GetPhoneNumberAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserPhoneNumberStore<TUser, TKey> store = this.GetPhoneNumberStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<string>(store.GetPhoneNumberAsync(val));
		}

		/// <summary>
		///     Set a user's phoneNumber
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="phoneNumber"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> SetPhoneNumberAsync(TKey userId, string phoneNumber)
		{
			this.ThrowIfDisposed();
			IUserPhoneNumberStore<TUser, TKey> store = this.GetPhoneNumberStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			await store.SetPhoneNumberAsync(user, phoneNumber).WithCurrentCulture();
			await store.SetPhoneNumberConfirmedAsync(user, false).WithCurrentCulture();
			await this.UpdateSecurityStampInternal(user).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Set a user's phoneNumber with the verification token
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="phoneNumber"></param>
		/// <param name="token"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> ChangePhoneNumberAsync(TKey userId, string phoneNumber, string token)
		{
			this.ThrowIfDisposed();
			IUserPhoneNumberStore<TUser, TKey> store = this.GetPhoneNumberStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (await TaskExtensions.WithCurrentCulture<bool>(this.VerifyChangePhoneNumberTokenAsync(userId, token, phoneNumber)))
			{
				await store.SetPhoneNumberAsync(user, phoneNumber).WithCurrentCulture();
				await store.SetPhoneNumberConfirmedAsync(user, true).WithCurrentCulture();
				await this.UpdateSecurityStampInternal(user).WithCurrentCulture();
				return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
			}
			return IdentityResult.Failed(Resources.InvalidToken);
		}

		/// <summary>
		///     Returns true if the user's phone number has been confirmed
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<bool> IsPhoneNumberConfirmedAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserPhoneNumberStore<TUser, TKey> store = this.GetPhoneNumberStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<bool>(store.GetPhoneNumberConfirmedAsync(val));
		}

		internal async Task<SecurityToken> CreateSecurityTokenAsync(TKey userId)
		{
			Encoding unicode = Encoding.Unicode;
			return new SecurityToken(unicode.GetBytes(await TaskExtensions.WithCurrentCulture<string>(this.GetSecurityStampAsync(userId))));
		}

		/// <summary>
		///     Generate a code that the user can use to change their phone number to a specific number
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="phoneNumber"></param>
		/// <returns></returns>
		public virtual async Task<string> GenerateChangePhoneNumberTokenAsync(TKey userId, string phoneNumber)
		{
			this.ThrowIfDisposed();
			return Rfc6238AuthenticationService.GenerateCode(await TaskExtensions.WithCurrentCulture<SecurityToken>(this.CreateSecurityTokenAsync(userId)), phoneNumber).ToString("D6", CultureInfo.InvariantCulture);
		}

		/// <summary>
		///     Verify the code is valid for a specific user and for a specific phone number
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="token"></param>
		/// <param name="phoneNumber"></param>
		/// <returns></returns>
		public virtual async Task<bool> VerifyChangePhoneNumberTokenAsync(TKey userId, string token, string phoneNumber)
		{
			this.ThrowIfDisposed();
			SecurityToken securityToken = await TaskExtensions.WithCurrentCulture<SecurityToken>(this.CreateSecurityTokenAsync(userId));
			if (securityToken != null && int.TryParse(token, out int code))
			{
				return Rfc6238AuthenticationService.ValidateCode(securityToken, code, phoneNumber);
			}
			return false;
		}

		/// <summary>
		///     Verify a user token with the specified purpose
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="purpose"></param>
		/// <param name="token"></param>
		/// <returns></returns>
		public virtual async Task<bool> VerifyUserTokenAsync(TKey userId, string purpose, string token)
		{
			this.ThrowIfDisposed();
			if (this.UserTokenProvider == null)
			{
				throw new NotSupportedException(Resources.NoTokenProvider);
			}
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<bool>(this.UserTokenProvider.ValidateAsync(purpose, token, this, val));
		}

		/// <summary>
		///     Get a user token for a specific purpose
		/// </summary>
		/// <param name="purpose"></param>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<string> GenerateUserTokenAsync(string purpose, TKey userId)
		{
			this.ThrowIfDisposed();
			if (this.UserTokenProvider == null)
			{
				throw new NotSupportedException(Resources.NoTokenProvider);
			}
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<string>(this.UserTokenProvider.GenerateAsync(purpose, this, val));
		}

		/// <summary>
		///     Register a two factor authentication provider with the TwoFactorProviders mapping
		/// </summary>
		/// <param name="twoFactorProvider"></param>
		/// <param name="provider"></param>
		public virtual void RegisterTwoFactorProvider(string twoFactorProvider, IUserTokenProvider<TUser, TKey> provider)
		{
			ThrowIfDisposed();
			if (twoFactorProvider == null)
			{
				throw new ArgumentNullException("twoFactorProvider");
			}
			if (provider == null)
			{
				throw new ArgumentNullException("provider");
			}
			TwoFactorProviders[twoFactorProvider] = provider;
		}

		/// <summary>
		///     Returns a list of valid two factor providers for a user
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<IList<string>> GetValidTwoFactorProvidersAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			List<string> results = new List<string>();
			foreach (KeyValuePair<string, IUserTokenProvider<TUser, TKey>> item in (IEnumerable<KeyValuePair<string, IUserTokenProvider<TUser, TKey>>>)this.TwoFactorProviders)
			{
				KeyValuePair<string, IUserTokenProvider<TUser, TKey>> f = item;
				if (await TaskExtensions.WithCurrentCulture<bool>(f.Value.IsValidProviderForUserAsync(this, user)))
				{
					results.Add(f.Key);
				}
				f = default(KeyValuePair<string, IUserTokenProvider<TUser, TKey>>);
			}
			return results;
		}

		/// <summary>
		///     Verify a two factor token with the specified provider
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="twoFactorProvider"></param>
		/// <param name="token"></param>
		/// <returns></returns>
		public virtual async Task<bool> VerifyTwoFactorTokenAsync(TKey userId, string twoFactorProvider, string token)
		{
			this.ThrowIfDisposed();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (!this._factors.ContainsKey(twoFactorProvider))
			{
				throw new NotSupportedException(string.Format(CultureInfo.CurrentCulture, Resources.NoTwoFactorProvider, new object[1]
				{
					twoFactorProvider
				}));
			}
			return await TaskExtensions.WithCurrentCulture<bool>(this._factors[twoFactorProvider].ValidateAsync(twoFactorProvider, token, this, val));
		}

		/// <summary>
		///     Get a token for a specific two factor provider
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="twoFactorProvider"></param>
		/// <returns></returns>
		public virtual async Task<string> GenerateTwoFactorTokenAsync(TKey userId, string twoFactorProvider)
		{
			this.ThrowIfDisposed();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (!this._factors.ContainsKey(twoFactorProvider))
			{
				throw new NotSupportedException(string.Format(CultureInfo.CurrentCulture, Resources.NoTwoFactorProvider, new object[1]
				{
					twoFactorProvider
				}));
			}
			return await TaskExtensions.WithCurrentCulture<string>(this._factors[twoFactorProvider].GenerateAsync(twoFactorProvider, this, val));
		}

		/// <summary>
		///     Notify a user with a token using a specific two-factor authentication provider's Notify method
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="twoFactorProvider"></param>
		/// <param name="token"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> NotifyTwoFactorTokenAsync(TKey userId, string twoFactorProvider, string token)
		{
			this.ThrowIfDisposed();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (!this._factors.ContainsKey(twoFactorProvider))
			{
				throw new NotSupportedException(string.Format(CultureInfo.CurrentCulture, Resources.NoTwoFactorProvider, new object[1]
				{
					twoFactorProvider
				}));
			}
			await this._factors[twoFactorProvider].NotifyAsync(token, this, val).WithCurrentCulture();
			return IdentityResult.Success;
		}

		internal IUserTwoFactorStore<TUser, TKey> GetUserTwoFactorStore()
		{
			IUserTwoFactorStore<TUser, TKey> obj = Store as IUserTwoFactorStore<TUser, TKey>;
			if (obj == null)
			{
				throw new NotSupportedException(Resources.StoreNotIUserTwoFactorStore);
			}
			return obj;
		}

		/// <summary>
		///     Get whether two factor authentication is enabled for a user
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<bool> GetTwoFactorEnabledAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserTwoFactorStore<TUser, TKey> store = this.GetUserTwoFactorStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<bool>(store.GetTwoFactorEnabledAsync(val));
		}

		/// <summary>
		///     Set whether a user has two factor authentication enabled
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="enabled"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> SetTwoFactorEnabledAsync(TKey userId, bool enabled)
		{
			this.ThrowIfDisposed();
			IUserTwoFactorStore<TUser, TKey> store = this.GetUserTwoFactorStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			await store.SetTwoFactorEnabledAsync(user, enabled).WithCurrentCulture();
			await this.UpdateSecurityStampInternal(user).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Send an email to the user
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="subject"></param>
		/// <param name="body"></param>
		/// <returns></returns>
		public virtual async Task SendEmailAsync(TKey userId, string subject, string body)
		{
			this.ThrowIfDisposed();
			if (this.EmailService != null)
			{
				IdentityMessage identityMessage = new IdentityMessage();
				IdentityMessage identityMessage2 = identityMessage;
				identityMessage2.Destination = await TaskExtensions.WithCurrentCulture<string>(this.GetEmailAsync(userId));
				identityMessage.Subject = subject;
				identityMessage.Body = body;
				await this.EmailService.SendAsync(identityMessage).WithCurrentCulture();
			}
		}

		/// <summary>
		///     Send a user a sms message
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="message"></param>
		/// <returns></returns>
		public virtual async Task SendSmsAsync(TKey userId, string message)
		{
			this.ThrowIfDisposed();
			if (this.SmsService != null)
			{
				IdentityMessage identityMessage = new IdentityMessage();
				IdentityMessage identityMessage2 = identityMessage;
				identityMessage2.Destination = await TaskExtensions.WithCurrentCulture<string>(this.GetPhoneNumberAsync(userId));
				identityMessage.Body = message;
				await this.SmsService.SendAsync(identityMessage).WithCurrentCulture();
			}
		}

		internal IUserLockoutStore<TUser, TKey> GetUserLockoutStore()
		{
			IUserLockoutStore<TUser, TKey> obj = Store as IUserLockoutStore<TUser, TKey>;
			if (obj == null)
			{
				throw new NotSupportedException(Resources.StoreNotIUserLockoutStore);
			}
			return obj;
		}

		/// <summary>
		///     Returns true if the user is locked out
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<bool> IsLockedOutAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserLockoutStore<TUser, TKey> store = this.GetUserLockoutStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (!(await TaskExtensions.WithCurrentCulture<bool>(store.GetLockoutEnabledAsync(user))))
			{
				return false;
			}
			return await TaskExtensions.WithCurrentCulture<DateTimeOffset>(store.GetLockoutEndDateAsync(user)) >= DateTimeOffset.UtcNow;
		}

		/// <summary>
		///     Sets whether lockout is enabled for this user
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="enabled"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> SetLockoutEnabledAsync(TKey userId, bool enabled)
		{
			this.ThrowIfDisposed();
			IUserLockoutStore<TUser, TKey> store = this.GetUserLockoutStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			await store.SetLockoutEnabledAsync(user, enabled).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Returns whether lockout is enabled for the user
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<bool> GetLockoutEnabledAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserLockoutStore<TUser, TKey> store = this.GetUserLockoutStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<bool>(store.GetLockoutEnabledAsync(val));
		}

		/// <summary>
		///     Returns when the user is no longer locked out, dates in the past are considered as not being locked out
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<DateTimeOffset> GetLockoutEndDateAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserLockoutStore<TUser, TKey> store = this.GetUserLockoutStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<DateTimeOffset>(store.GetLockoutEndDateAsync(val));
		}

		/// <summary>
		///     Sets the when a user lockout ends
		/// </summary>
		/// <param name="userId"></param>
		/// <param name="lockoutEnd"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> SetLockoutEndDateAsync(TKey userId, DateTimeOffset lockoutEnd)
		{
			this.ThrowIfDisposed();
			IUserLockoutStore<TUser, TKey> store = this.GetUserLockoutStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (!(await TaskExtensions.WithCurrentCulture<bool>(store.GetLockoutEnabledAsync(user))))
			{
				return IdentityResult.Failed(Resources.LockoutNotEnabled);
			}
			await store.SetLockoutEndDateAsync(user, lockoutEnd).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		/// Increments the access failed count for the user and if the failed access account is greater than or equal
		/// to the MaxFailedAccessAttempsBeforeLockout, the user will be locked out for the next DefaultAccountLockoutTimeSpan
		/// and the AccessFailedCount will be reset to 0. This is used for locking out the user account.
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> AccessFailedAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserLockoutStore<TUser, TKey> store = this.GetUserLockoutStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (await TaskExtensions.WithCurrentCulture<int>(store.IncrementAccessFailedCountAsync(user)) >= this.MaxFailedAccessAttemptsBeforeLockout)
			{
				await store.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.Add(this.DefaultAccountLockoutTimeSpan)).WithCurrentCulture();
				await store.ResetAccessFailedCountAsync(user).WithCurrentCulture();
			}
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Resets the access failed count for the user to 0
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<IdentityResult> ResetAccessFailedCountAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserLockoutStore<TUser, TKey> store = this.GetUserLockoutStore();
			TUser user = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (user == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			if (await TaskExtensions.WithCurrentCulture<int>(this.GetAccessFailedCountAsync(((IUser<TKey>)user).Id)) == 0)
			{
				return IdentityResult.Success;
			}
			await store.ResetAccessFailedCountAsync(user).WithCurrentCulture();
			return await TaskExtensions.WithCurrentCulture<IdentityResult>(this.UpdateAsync(user));
		}

		/// <summary>
		///     Returns the number of failed access attempts for the user
		/// </summary>
		/// <param name="userId"></param>
		/// <returns></returns>
		public virtual async Task<int> GetAccessFailedCountAsync(TKey userId)
		{
			this.ThrowIfDisposed();
			IUserLockoutStore<TUser, TKey> store = this.GetUserLockoutStore();
			TUser val = await TaskExtensions.WithCurrentCulture<TUser>(this.FindByIdAsync(userId));
			if (val == null)
			{
				throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound, new object[1]
				{
					userId
				}));
			}
			return await TaskExtensions.WithCurrentCulture<int>(store.GetAccessFailedCountAsync(val));
		}

		private void ThrowIfDisposed()
		{
			if (_disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
		}

		/// <summary>
		///     When disposing, actually dipose the store
		/// </summary>
		/// <param name="disposing"></param>
		protected virtual void Dispose(bool disposing)
		{
			if (disposing && !_disposed)
			{
				Store.Dispose();
				_disposed = true;
			}
		}
	}
}
