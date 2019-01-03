using System.Globalization;
using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Used to validate that passwords are a minimum length
	/// </summary>
	public class MinimumLengthValidator : IIdentityValidator<string>
	{
		/// <summary>
		///     Minimum required length for the password
		/// </summary>
		public int RequiredLength
		{
			get;
			set;
		}

		/// <summary>
		///     Constructor
		/// </summary>
		/// <param name="requiredLength"></param>
		public MinimumLengthValidator(int requiredLength)
		{
			RequiredLength = requiredLength;
		}

		/// <summary>
		///     Ensures that the password is of the required length
		/// </summary>
		/// <param name="item"></param>
		/// <returns></returns>
		public virtual Task<IdentityResult> ValidateAsync(string item)
		{
			if (string.IsNullOrWhiteSpace(item) || item.Length < RequiredLength)
			{
				return Task.FromResult(IdentityResult.Failed(string.Format(CultureInfo.CurrentCulture, Resources.PasswordTooShort, new object[1]
				{
					RequiredLength
				})));
			}
			return Task.FromResult(IdentityResult.Success);
		}
	}
}
