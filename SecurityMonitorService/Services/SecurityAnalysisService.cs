using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using SecurityMonitorService.Models;


namespace SecurityMonitorService.Services
{
    public class SecurityAnalysisService
    {
        private readonly IConfiguration _config;
        private readonly HttpClient _http;
        private readonly ILogger<SecurityAnalysisService> _logger;

        public SecurityAnalysisService(IConfiguration config, IHttpClientFactory httpClientFactory, ILogger<SecurityAnalysisService> logger)
        {
            _config = config;
            _http = httpClientFactory.CreateClient();
            _logger = logger;
        }

        public async Task<SecurityAnalysisResult> AnalyzeLogsAsync(List<LogEntry> logs)
        {
            var logSummary = string.Join("\n", logs.Select(l =>
                $"[{l.LogTimeStamp:HH:mm:ss}] {l.LogType} | {l.AffectedEmail ?? "unknown"} | {l.IpAddress ?? "unknown"} | {l.LogDescription}"));

            var model = _config["OllamaSettings:Model"] ?? "kimi-k2.5";
            var baseUrl = _config["OllamaSettings:BaseUrl"] ?? "http://localhost:11434";

            var requestBody = new
            {
                model,
                messages = new object[]
                {
                    new
                    {
                        role = "system",
                        content = "You are a security analyst. Analyze the provided authentication logs and respond ONLY with valid JSON in this exact format: { \"severityLevel\": 0, \"attackType\": \"\", \"summary\": \"\", \"recommendation\": \"\" }. SeverityLevel: 0=normal, 1=low, 2=medium, 3=high, 4=critical. Do not include any text outside the JSON."
                    },
                    new
                    {
                        role = "user",
                        content = $"Analyze these auth logs:\n{logSummary}"
                    }
                }
            };

            var json = JsonSerializer.Serialize(requestBody);
            var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/v1/chat/completions");
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _http.SendAsync(request);
            var responseJson = await response.Content.ReadAsStringAsync();

            _logger.LogInformation("[SecurityMonitor] Ollama råsvar: {response}", responseJson);

            using var doc = JsonDocument.Parse(responseJson);
            var root = doc.RootElement;

            if (!root.TryGetProperty("choices", out var choices))
            {
                _logger.LogError("[SecurityMonitor] Uventet svar fra Ollama — mangler 'choices'. Råsvar: {response}", responseJson);
                return new SecurityAnalysisResult { AttackType = "Ukendt", Summary = "Kunne ikke parse Ollama svar" };
            }

            var content = choices[0]
                .GetProperty("message")
                .GetProperty("content")
                .GetString() ?? "{}";

            // Strip markdown code blocks hvis Claude wrapper JSON i ```
            content = content.Trim();
            if (content.StartsWith("```"))
            {
                content = content.Split('\n', 2)[1];
                content = content[..content.LastIndexOf("```")].Trim();
            }

            return JsonSerializer.Deserialize<SecurityAnalysisResult>(content, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? new SecurityAnalysisResult();
        }

        public async Task SendAlertEmailAsync(SecurityAnalysisResult result)
        {
            var adminEmail = _config["SmtpSettings:AdminAlertEmail"]!;
            var from = _config["SmtpSettings:From"]!;
            var password = _config["SmtpSettings:Password"]!;

            var message = new MailMessage(from, adminEmail)
            {
                Subject = $"[SIKKERHEDSALARM] {result.AttackType} — Sværhedsgrad {result.SeverityLevel}/4",
                Body = $@"Sikkerhedsalarm fra DanPlanner

Angrebstype  : {result.AttackType}
Sværhedsgrad : {result.SeverityLevel}/4

Opsummering:
{result.Summary}

Anbefaling:
{result.Recommendation}

---
Denne besked er genereret automatisk af SecurityMonitorService.
"
            };

            using var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                Credentials = new NetworkCredential(from, password),
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false
            };

            await Task.Run(() => smtp.Send(message));
            _logger.LogWarning("[SecurityMonitor] Alert email sendt til {email}", adminEmail);
        }
    }
}
