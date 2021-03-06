namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Represents a linked login for a user (i.e. a facebook/google account)
	/// </summary>
	public sealed class UserLoginInfo
	{
		/// <summary>
		///     Provider for the linked login, i.e. Facebook, Google, etc.
		/// </summary>
		public string LoginProvider
		{
			get;
			set;
		}

		/// <summary>
		///     User specific key for the login provider
		/// </summary>
		public string ProviderKey
		{
			get;
			set;
		}

		/// <summary>
		///     Constructor
		/// </summary>
		/// <param name="loginProvider"></param>
		/// <param name="providerKey"></param>
		public UserLoginInfo(string loginProvider, string providerKey)
		{
			LoginProvider = loginProvider;
			ProviderKey = providerKey;
		}
	}
}
