namespace Danplanner.Domain.Interfaces
{
    public interface ITranslationService
    {
        Task<string> TranslateTextAsync(string text, string targetLanguage);
    }
}
