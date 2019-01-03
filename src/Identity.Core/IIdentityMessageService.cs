using System.Threading.Tasks;

namespace Microsoft.IdentityFramework
{
	/// <summary>
	///     Expose a way to send messages (i.e. email/sms)
	/// </summary>
	public interface IIdentityMessageService
	{
		/// <summary>
		///     This method should send the message
		/// </summary>
		/// <param name="message"></param>
		/// <returns></returns>
		Task SendAsync(IdentityMessage message);
	}
}
