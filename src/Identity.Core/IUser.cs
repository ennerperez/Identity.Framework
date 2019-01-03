namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Minimal interface for a user with id and username
	/// </summary>
	public interface IUser : IUser<string>
	{
	}
	/// <summary>
	///     Minimal interface for a user with id and username
	/// </summary>
	/// <typeparam name="TKey"></typeparam>
	public interface IUser<out TKey>
	{
		/// <summary>
		///     Unique key for the user
		/// </summary>
		TKey Id
		{
			get;
		}

		/// <summary>
		///     Unique username
		/// </summary>
		string UserName
		{
			get;
			set;
		}
	}
}
