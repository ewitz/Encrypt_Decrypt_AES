using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Encrypt_Decrypt_AES.Models;
using Encrypt_Decrypt_AES.Controllers;
using Microsoft.Extensions.Configuration;

namespace Encrypt_Decrypt_AES.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration;
        public HomeController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public IActionResult Index()
        {
            EncryptDecryptModel encryptDecryptModel = new EncryptDecryptModel();
            return View(encryptDecryptModel);
        }

        [HttpPost]
        public IActionResult Index(EncryptDecryptModel EncDecModel)
        {
            EncryptDecryptModel newModel = new EncryptDecryptModel();
            SecurityController securityController = new SecurityController(_configuration);
            newModel.plainText = EncDecModel.plainText;
            newModel.cipherText = EncDecModel.cipherText;
            if (EncDecModel.plainText  == null && EncDecModel.cipherText == null)
            {
                return View();
            }
            else if (EncDecModel.plainText != null && EncDecModel.cipherText != null)
            {
                return View(EncDecModel);
            }
            else if (EncDecModel.plainText != null && EncDecModel.cipherText == null)
            {
                newModel.cipherText = securityController.ObtainCipherText(EncDecModel.plainText);
            }
            else if (EncDecModel.plainText == null && EncDecModel.cipherText != null)
            {
                newModel.plainText = securityController.ObtainPlaintText(EncDecModel.cipherText);
            }
            return View(newModel);
        }

        public IActionResult FIPS140()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
