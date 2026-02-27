using Danplanner.Domain.Interfaces;

namespace Danplanner.Application.Services
{
    public class ContentTranslationHandler
    {
        private readonly ITranslationService _translationService;

        public ContentTranslationHandler(ITranslationService translationService)
        {
            _translationService = translationService;
        }

        public async Task<string> TranslationContentAsync(string text, string languageCode)
        {
            return await _translationService.TranslateTextAsync(text, languageCode);
        }
    }
}
