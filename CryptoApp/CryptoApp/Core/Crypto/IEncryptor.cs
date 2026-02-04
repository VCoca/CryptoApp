using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoApp.Core.Crypto
{
    public interface IEncryptor
    {
        int BlockSize { get; }
        byte[] Encrypt(byte[] data, byte[] key, byte[] iv);
        byte[] Decrypt(byte[] data, byte[] key, byte[] iv);
    }
}
