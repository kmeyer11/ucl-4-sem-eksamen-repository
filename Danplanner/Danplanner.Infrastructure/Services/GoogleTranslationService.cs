using Danplanner.Domain.Interfaces;
using Google.Cloud.Translate.V3;

namespace Danplanner.Infrastructure.Services
{
    public class GoogleTranslationService : ITranslationService
    {
        private readonly TranslationServiceClient _client;
        private readonly string _projectId;

        public GoogleTranslationService(string projectId)
        {
            _projectId = projectId;
            _client = TranslationServiceClient.Create();
        }

        public async Task<string> TranslateTextAsync(string text, string targetLanguageCode)
        {
            var response = await _client.TranslateTextAsync(
                contents: new[] { text },
                targetLanguageCode: targetLanguageCode,
                parent: $"projects/{_projectId}/locations/global");

            return response.Translations.First().TranslatedText;
        }
    }
}

