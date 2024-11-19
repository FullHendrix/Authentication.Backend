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
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            var textBytes = Encoding.ASCII.GetBytes(value);
            var encriptedTextBytes = rsa.Encrypt(textBytes, RSAEncryptionPadding.Pkcs1);
            var encriptedText = Convert.ToBase64String(encriptedTextBytes);
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