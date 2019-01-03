namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Return result for IPasswordHasher
	/// </summary>
	public enum PasswordVerificationResult
	{
		/// <summary>
		///     Password verification failed
		/// </summary>
		Failed,
		/// <summary>
		///     Success
		/// </summary>
		Success,
		/// <summary>
		///     Success but should update and rehash the password
		/// </summary>
		SuccessRehashNeeded
	}
}
