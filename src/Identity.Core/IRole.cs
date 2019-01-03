namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Mimimal set of data needed to persist role information
	/// </summary>
	public interface IRole : IRole<string>
	{
	}
	/// <summary>
	///     Mimimal set of data needed to persist role information
	/// </summary>
	/// <typeparam name="TKey"></typeparam>
	public interface IRole<out TKey>
	{
		/// <summary>
		///     Id of the role
		/// </summary>
		TKey Id
		{
			get;
		}

		/// <summary>
		///     Name of the role
		/// </summary>
		string Name
		{
			get;
			set;
		}
	}
}
