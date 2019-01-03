using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.IdentityFramework
{
	internal static class Rfc6238AuthenticationService
	{
		private static readonly DateTime _unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

		private static readonly TimeSpan _timestep = TimeSpan.FromMinutes(3.0);

		private static readonly Encoding _encoding = new UTF8Encoding(false, true);

		private static int ComputeTotp(HashAlgorithm hashAlgorithm, ulong timestepNumber, string modifier)
		{
			byte[] bytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((long)timestepNumber));
			byte[] array = hashAlgorithm.ComputeHash(ApplyModifier(bytes, modifier));
			int num = array[array.Length - 1] & 0xF;
			return (((array[num] & 0x7F) << 24) | ((array[num + 1] & 0xFF) << 16) | ((array[num + 2] & 0xFF) << 8) | (array[num + 3] & 0xFF)) % 1000000;
		}

		private static byte[] ApplyModifier(byte[] input, string modifier)
		{
			if (string.IsNullOrEmpty(modifier))
			{
				return input;
			}
			byte[] bytes = _encoding.GetBytes(modifier);
			byte[] array = new byte[checked(input.Length + bytes.Length)];
			Buffer.BlockCopy(input, 0, array, 0, input.Length);
			Buffer.BlockCopy(bytes, 0, array, input.Length, bytes.Length);
			return array;
		}

		private static ulong GetCurrentTimeStepNumber()
		{
			return (ulong)((DateTime.UtcNow - _unixEpoch).Ticks / _timestep.Ticks);
		}

		public static int GenerateCode(SecurityToken securityToken, string modifier = null)
		{
			if (securityToken == null)
			{
				throw new ArgumentNullException("securityToken");
			}
			ulong currentTimeStepNumber = GetCurrentTimeStepNumber();
			using (HMACSHA1 hashAlgorithm = new HMACSHA1(securityToken.GetDataNoClone()))
			{
				return ComputeTotp(hashAlgorithm, currentTimeStepNumber, modifier);
			}
		}

		public static bool ValidateCode(SecurityToken securityToken, int code, string modifier = null)
		{
			if (securityToken == null)
			{
				throw new ArgumentNullException("securityToken");
			}
			ulong currentTimeStepNumber = GetCurrentTimeStepNumber();
			using (HMACSHA1 hashAlgorithm = new HMACSHA1(securityToken.GetDataNoClone()))
			{
				for (int i = -2; i <= 2; i++)
				{
					if (ComputeTotp(hashAlgorithm, (ulong)((long)currentTimeStepNumber + (long)i), modifier) == code)
					{
						return true;
					}
				}
			}
			return false;
		}
	}
}
