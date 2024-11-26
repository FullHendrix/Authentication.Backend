using Intelica.Infrastructure.Library.Cache.Interface;
using System.Security.Cryptography;
using System.Text;
namespace Intelica.Authentication.API.Common.Encriptation
{
    public class GenericRSA(IGenericCache genericCache) : IGenericRSA
    {
        public string Encript(string publicKey, string value)
        {
            var publicKeyBytes = Convert.FromBase64String(publicKey);
            var textBytes = Encoding.ASCII.GetBytes(value);
            RSACryptoServiceProvider RsaCsp = new();
            RsaCsp.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            byte[] encryptedData = RsaCsp.Encrypt(textBytes, true);
            var encriptedText = Convert.ToBase64String(encryptedData);
            return encriptedText;
        }
        public string Decript(string privateKey, string value)
        {
            var privateKeyBytes = Convert.FromBase64String(privateKey);
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
            var encryptedTextBytes = Convert.FromBase64String(value);
            var decryptedTextBytes = rsa.Decrypt(encryptedTextBytes, RSAEncryptionPadding.Pkcs1);
            var decryptedText = Encoding.UTF8.GetString(decryptedTextBytes);
            return decryptedText;
        }
        public KeyValuePair<string, string> GetKeys()
        {
            using var rsa = RSA.Create(2048);
            var privateKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
            var publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
            genericCache.Set(privateKey, publicKey);
            return new KeyValuePair<string, string>(publicKey, privateKey);
        }
    }
}