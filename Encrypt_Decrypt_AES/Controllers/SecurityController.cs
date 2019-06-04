using System;
using Microsoft.AspNetCore.Mvc;
using Encrypt_Decrypt_AES.Models;
using System.Security.Cryptography;
using System.IO;
using Microsoft.Extensions.Configuration;

namespace Encrypt_Decrypt_AES.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecurityController : ControllerBase
    {
        //Used for method figuring out which environment this service is in:
        private readonly IConfiguration _configuration;
        private readonly string _configIV;
        private readonly string _configKey;
        // The class constructor.
        public SecurityController(IConfiguration configuration)
        {
            _configuration = configuration;
            //if (Environment.MachineName == "MontBlanc" || Environment.MachineName.StartsWith("ec2"))
            //{
            //    _configIV = _configuration["Development:IV"];
            //    _configKey = _configuration["Development:Key"];
            //}
            _configIV = _configuration["Development:IV"];
            _configKey = _configuration["Development:Key"];

        }
        [HttpPost]
        [Route("encrypt")]
        public ActionResult<EncryptDecryptModel> GetCipherText(EncryptDecryptModel model)
        {
            try
            {
                if (string.IsNullOrEmpty(model.plainText) && string.IsNullOrEmpty(model.cipherText))
                {
                    return NoContent();
                }
                string original = model.plainText;
                using (AesCng myAes = new AesCng())
                {
                    //myAes.GenerateIV();
                    //myAes.GenerateKey();
                    myAes.IV = Convert.FromBase64String(_configIV);
                    myAes.Key = Convert.FromBase64String(_configKey);
                    // Encrypt the string to an array of bytes.
                    string cipherText = EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);
                    // Decrypt the bytes to a string.
                    byte[] encrption = Convert.FromBase64String(cipherText);
                    string decryptedPlaintText = DecryptStringFromBytes_Aes(encrption, myAes.Key, myAes.IV);
                    model.cipherText = cipherText;
                }
                return Ok(model);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex);
            }
        }
        public string ObtainCipherText(string plainText)
        {
            using (AesCng myAes = new AesCng())
            {
                //myAes.GenerateKey();
                //myAes.GenerateIV();
                myAes.IV = Convert.FromBase64String(_configIV);
                myAes.Key = Convert.FromBase64String(_configKey);
                // Encrypt the string to an array of bytes.
                string cipherText = EncryptStringToBytes_Aes(plainText, myAes.Key, myAes.IV);
                // Decrypt the bytes to a string.
                byte[] encrption = Convert.FromBase64String(cipherText);
                string decryptedPlaintText = DecryptStringFromBytes_Aes(encrption, myAes.Key, myAes.IV);
                //Display the original data and the decrypted data.
                return cipherText;
            }
        }
        public string ObtainPlaintText(string cipherText)
        {
            using (AesCng aesAlg = new AesCng())
            {
                string plainText;
                aesAlg.IV = Convert.FromBase64String(_configIV);
                aesAlg.Key = Convert.FromBase64String(_configKey);
                // Declare the string used to hold
                // the decrypted text.
                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                byte[] cipherBytes = Convert.FromBase64String(cipherText);
                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plainText = srDecrypt.ReadToEnd();
                        }
                    }
                }
                return plainText;
            }
        }
        static string EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an AesCryptoServiceProvider object
            // with the specified key and IV.
            using (AesCng aesAlg = new AesCng())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            // Return string from the encrypted bytes from the memory stream.
            string cipherText = Convert.ToBase64String(encrypted);
            return cipherText;
        }
        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;
            // Create an AesCryptoServiceProvider object
            // with the specified key and IV.
            using (AesCng aesAlg = new AesCng())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
        [HttpPost]
        [Route("decrypt")]
        public ActionResult<EncryptDecryptModel> GetPlaintext(EncryptDecryptModel model)
        {
            try
            {
                using (AesCng aesAlg = new AesCng())
                {
                    aesAlg.IV = Convert.FromBase64String(_configIV);
                    aesAlg.Key = Convert.FromBase64String(_configKey);

                    // Declare the string used to hold
                    // the decrypted text.
                    string b64CipherText = model.cipherText;
                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    byte[] cipherText = Convert.FromBase64String(b64CipherText);
                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            //csDecrypt.Read(cipherText, 0, cipherText.Length);
                            //plaintext = Convert.ToBase64String(msDecrypt.ToArray());
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                // Read the decrypted bytes from the decrypting stream
                                // and place them in a string.
                                model.plainText = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                    return Ok(model);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex);
            }
        }
    }
}