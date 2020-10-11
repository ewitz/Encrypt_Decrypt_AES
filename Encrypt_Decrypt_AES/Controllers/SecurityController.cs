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
        //private readonly string _configIV;
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
            //_configIV = _configuration["Development:IV"];
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
                using (AesCryptoServiceProvider myAes = new AesCryptoServiceProvider())
                {
                    //myAes.GenerateKey();                   
                    myAes.Key = Convert.FromBase64String(_configKey);
                    // Encrypt the string to an array of bytes.                   
                    string cipherText = EncryptString(original, myAes.Key);
                    string decryptedPlaintText = DecryptString(cipherText, myAes.Key);
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
            using (AesCryptoServiceProvider myAes = new AesCryptoServiceProvider())
            {
                //myAes.GenerateKey();
                myAes.Key = Convert.FromBase64String(_configKey);
                // Encrypt the string to an array of bytes.
                string cipherText = EncryptString(plainText, myAes.Key);
                // Decrypt the bytes to a string.
                byte[] encrption = Convert.FromBase64String(cipherText);
                string decryptedPlaintText = DecryptString(cipherText, myAes.Key);

                //Display the original data and the decrypted data.
                return cipherText;
            }
        }
        public string ObtainPlaintText(string cipherText)
        {
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                string plainText;
                aesAlg.Key = Convert.FromBase64String(_configKey);
                plainText = DecryptString(cipherText, aesAlg.Key);
                return plainText;
            }
        }

        public static string EncryptString(string message, byte[] key)
        {
            var aes = new AesCryptoServiceProvider();
            var iv = aes.IV;
            using (var memStream = new System.IO.MemoryStream())
            {
                // Add IV to the first 16 bytes of encrypted value, we'll store it there for later decryption
                memStream.Write(iv, 0, iv.Length);
                using (var cryptStream = new CryptoStream(memStream, aes.CreateEncryptor(key, aes.IV), CryptoStreamMode.Write))
                {
                    using (var writer = new System.IO.StreamWriter(cryptStream))
                    {
                        writer.Write(message);
                    }
                }
                var buf = memStream.ToArray();
                return Convert.ToBase64String(buf, 0, buf.Length);
            }
        }

        public static string DecryptString(string encryptedValue, byte[] key)
        {
            var bytes = Convert.FromBase64String(encryptedValue);
            var aes = new AesCryptoServiceProvider();
            using (var memStream = new System.IO.MemoryStream(bytes))
            {
                var iv = new byte[16];
                memStream.Read(iv, 0, 16);  // Pull the IV from the first 16 bytes of the encrypted value
                using (var cryptStream = new CryptoStream(memStream, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read))
                {
                    using (var reader = new System.IO.StreamReader(cryptStream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
        }

        [HttpPost]
        [Route("decrypt")]
        public ActionResult<EncryptDecryptModel> GetPlaintext(EncryptDecryptModel model)
        {
            try
            {
                using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
                {
                    aesAlg.Key = Convert.FromBase64String(_configKey);

                    string b64CipherText = model.cipherText;
                    string decryptedTxt = DecryptString(b64CipherText, aesAlg.Key);

                    model.plainText = decryptedTxt;
                    return Ok(model);

                }
            }
            catch (Exception ex)
            {
                //TODO: Write to EventLog, Alert Error 
                return StatusCode(500, ex);
            }
        }
    }
}