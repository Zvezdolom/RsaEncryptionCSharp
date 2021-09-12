using System;
using System.Security.Cryptography;
using System.Text;

namespace RsaEncryptionCSharp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Creating keys");
            CreateRsaKeys(2048, "public.xml", "private.xml");
            Console.WriteLine("Keys created");

            string publicKeyString = GetKeyStringFromFile("public.xml");
            string privateKeyString = GetKeyStringFromFile("private.xml");

            string textToEncrypt = GenerateTestString();
            Console.WriteLine("Text: ");
            Console.WriteLine(textToEncrypt);
            Console.WriteLine("-------------------------------------------");

            string encryptedText = Encrypt(textToEncrypt, publicKeyString);
            Console.WriteLine("Encrypted Text: ");
            Console.WriteLine(encryptedText);
            Console.WriteLine("-------------------------------------------");

            string decryptedText = Decrypt(encryptedText, privateKeyString);

            Console.WriteLine("Decrypted Text: ");
            Console.WriteLine(decryptedText);

            Console.ReadLine();
        }
        public static void CreateRsaKeys(int dwKeySize, string pathPublic, string pathPrivate)
        {
            var cryptoServiceProvider = new RSACryptoServiceProvider(dwKeySize);
            var privateKey = cryptoServiceProvider.ExportParameters(true);
            var publicKey = cryptoServiceProvider.ExportParameters(false);

            string publicKeyString = GetKeyString(publicKey);
            string privateKeyString = GetKeyString(privateKey);

            WriteKeyStringToFile(pathPublic, publicKeyString);
            WriteKeyStringToFile(pathPrivate, privateKeyString);
        }
        public static string GetKeyString(RSAParameters key)
        {
            var stringWriter = new System.IO.StringWriter();
            var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xmlSerializer.Serialize(stringWriter, key);
            return stringWriter.ToString();
        }
        public static string GetKeyStringFromFile(string path)
        {
            using (System.IO.StreamReader sr = new System.IO.StreamReader(path))
            {
                return sr.ReadToEnd();
            }
        }
        public static void WriteKeyStringToFile(string path, string data)
        {
            using (System.IO.StreamWriter sw = new System.IO.StreamWriter(path, false, System.Text.Encoding.Default))
            {
                sw.WriteLine(data);
            }
        }
        public static string Encrypt(string textToEncrypt, string publicKeyString)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(textToEncrypt);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    rsa.FromXmlString(publicKeyString.ToString());
                    var encryptedData = rsa.Encrypt(bytesToEncrypt, true);
                    var base64Encrypted = Convert.ToBase64String(encryptedData);
                    return base64Encrypted;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
        public static string Decrypt(string textToDecrypt, string privateKeyString)
        {
            var bytesToDescrypt = Encoding.UTF8.GetBytes(textToDecrypt);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {                  
                    rsa.FromXmlString(privateKeyString);

                    var resultBytes = Convert.FromBase64String(textToDecrypt);
                    var decryptedBytes = rsa.Decrypt(resultBytes, true);
                    var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
                    return decryptedData.ToString();
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
        private static string GenerateTestString()
        {
            Guid opportinityId = Guid.NewGuid();
            Guid systemUserId = Guid.NewGuid();
            string currentTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("opportunityid={0}", opportinityId.ToString());
            sb.AppendFormat("&systemuserid={0}", systemUserId.ToString());
            sb.AppendFormat("&currenttime={0}", currentTime);

            return sb.ToString();
        }
    }
}