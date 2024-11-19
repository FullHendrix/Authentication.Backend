namespace Intelica.Authentication.API.Common.Encriptation
{
    public interface IGenericRSA
    {
        KeyValuePair<string, string> GetKeys();
        string Decript(string privateKey, string value);
        string Encript(string publicKey, string value);
    }
}