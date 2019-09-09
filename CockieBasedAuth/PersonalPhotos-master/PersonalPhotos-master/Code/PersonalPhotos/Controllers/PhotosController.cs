using System.IO;
using System.Threading.Tasks;
using Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PersonalPhotos.Models;

namespace PersonalPhotos.Controllers
{
    [Authorize]
    public class PhotosController : Controller
    {
        private readonly IFileStorage _fileStorage;
        private readonly IKeyGenerator _keyGenerator;
        private readonly IPhotoMetaData _photoMetaData;

        public PhotosController(IKeyGenerator keyGenerator,
            IPhotoMetaData photoMetaData, IFileStorage fileStorage)
        {
            _keyGenerator = keyGenerator;
            _photoMetaData = photoMetaData;
            _fileStorage = fileStorage;
        }

       
        public IActionResult Upload()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Upload(PhotoUploadViewModel model)
        {
            if (ModelState.IsValid)
            {
                var userName = User.Identity.Name;
                var uniqueKey = _keyGenerator.GetKey(userName);

                var fileName = Path.GetFileName(model.File.FileName);
                await _photoMetaData.SavePhotoMetaData(userName, model.Description, fileName);
                await _fileStorage.StoreFile(model.File, uniqueKey);
            }
            return RedirectToAction("Display");
        }

        public IActionResult Display()
        {
            var userName = User.Identity.Name;
            return View("Display", userName);
        }
    }
}