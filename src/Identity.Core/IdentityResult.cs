using System.Collections.Generic;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Represents the result of an identity operation
	/// </summary>
	public class IdentityResult
	{
		private static readonly IdentityResult _success = new IdentityResult(true);

		/// <summary>
		///     True if the operation was successful
		/// </summary>
		public bool Succeeded
		{
			get;
			private set;
		}

		/// <summary>
		///     List of errors
		/// </summary>
		public IEnumerable<string> Errors
		{
			get;
			private set;
		}

		/// <summary>
		///     Static success result
		/// </summary>
		/// <returns></returns>
		public static IdentityResult Success => _success;

		/// <summary>
		///     Failure constructor that takes error messages
		/// </summary>
		/// <param name="errors"></param>
		public IdentityResult(params string[] errors)
			: this((IEnumerable<string>)errors)
		{
		}

		/// <summary>
		///     Failure constructor that takes error messages
		/// </summary>
		/// <param name="errors"></param>
		public IdentityResult(IEnumerable<string> errors)
		{
			if (errors == null)
			{
				errors = new string[1]
				{
					Resources.DefaultError
				};
			}
			Succeeded = false;
			Errors = errors;
		}

		/// <summary>
		/// Constructor that takes whether the result is successful
		/// </summary>
		/// <param name="success"></param>
		protected IdentityResult(bool success)
		{
			Succeeded = success;
			Errors = new string[0];
		}

		/// <summary>
		///     Failed helper method
		/// </summary>
		/// <param name="errors"></param>
		/// <returns></returns>
		public static IdentityResult Failed(params string[] errors)
		{
			return new IdentityResult(errors);
		}
	}
}
