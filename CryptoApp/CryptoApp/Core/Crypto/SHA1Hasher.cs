using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace CryptoApp.Core.Crypto
{
    internal class SHA1Hasher
    {
        public static string SHA1Hash(byte[] data)
        {
            using var sha = SHA1.Create();
            byte[] hashBytes = sha.ComputeHash(data);
            return Convert.ToBase64String(hashBytes);
        }
    }
}
