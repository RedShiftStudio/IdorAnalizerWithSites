using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using HtmlAgilityPack;
using iTextSharp.text.pdf;
using iTextSharp.text;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using Spectre.Console;

namespace IdorAnalizerCSharp
{
    public class AdvancedIdorScanner
    {
        private readonly HttpClient _httpClient;
        private readonly List<string> _parameterPatterns = new List<string>
        {
            "id", "user", "user_id", "doc", "document", "file", "order",
            "profile", "account", "record", "item", "product", "invoice", "transaction",
            "me", "current", "self" // Добавлены ключевые слова из статьи
        };

        private readonly List<string> _authIndicators = new List<string>
        {
            "welcome", "hello", "profile", "settings", "dashboard",
            "account", "email", "username", "logout", "sign out",
            "password", "token", "session", "auth", "credential"
        };

        private readonly List<string> _errorIndicators = new List<string>
        {
            "access denied", "permission denied", "not authorized",
            "forbidden", "restricted", "invalid request", "error",
            "unauthorized", "not found", "does not exist"
        };

        private readonly List<string> _personalDataPatterns = new List<string>
        {
            @"\b[\w\.-]+@[\w\.-]+\.\w+\b",  // email
            @"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  // phone
            @"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",  // credit card
            @"\b\d{2}[- /.]\d{2}[- /.]\d{4}\b",  // date
            @"\b\d{9}\b"  // social security number
        };

        private readonly ConcurrentDictionary<string, bool> _testedUrls = new ConcurrentDictionary<string, bool>();
        private readonly ConcurrentBag<ScanResult> _results = new ConcurrentBag<ScanResult>();
        private readonly int _maxConcurrency;
        private readonly double _sensitivity;
        private readonly int _timeoutSeconds;
        private readonly HashSet<string> _discoveredIds = new HashSet<string>();
        private readonly List<string> _apiVersions = new List<string> { "v1", "v2", "v3", "1.0", "2.0", "3.0", "latest" };

        public AdvancedIdorScanner(HttpClient httpClient, int maxConcurrency = 5, double sensitivity = 0.8, int timeoutSeconds = 10)
        {
            _httpClient = httpClient;
            _maxConcurrency = maxConcurrency;
            _sensitivity = sensitivity;
            _timeoutSeconds = timeoutSeconds;
        }

        // Добавлены новые методы для обнаружения различных типов IDOR
        private (bool isVulnerable, double confidence, string details) AnalyzeResponse(string originalResponse, string modifiedResponse,
            HttpStatusCode originalStatus, HttpStatusCode modifiedStatus, string testType = "basic")
        {
            // Анализ статус кодов
            if ((int)modifiedStatus != (int)originalStatus)
            {
                if ((int)modifiedStatus == 200 && ((int)originalStatus == 403 || (int)originalStatus == 404))
                {
                    return (true, 0.95, $"Different status codes: {originalStatus} -> {modifiedStatus} (access granted) - {testType} test");
                }
                else if (((int)modifiedStatus == 403 || (int)modifiedStatus == 404) && (int)originalStatus == 200)
                {
                    return (false, 0.8, $"Different status codes: {originalStatus} -> {modifiedStatus} (access denied as expected) - {testType} test");
                }
                else if ((int)modifiedStatus == 500)
                {
                    return (true, 0.7, $"Server error 500 with modified parameter - {testType} test");
                }
            }

            double confidence = 0.5;
            string details = "";

            // Анализ содержимого
            originalResponse = originalResponse.ToLower();
            modifiedResponse = modifiedResponse.ToLower();

            // Проверка авторизованного контента
            int authCountOriginal = _authIndicators.Count(indicator => originalResponse.Contains(indicator));
            int authCountModified = _authIndicators.Count(indicator => modifiedResponse.Contains(indicator));

            // Проверка ошибок доступа
            int errorCountOriginal = _errorIndicators.Count(indicator => originalResponse.Contains(indicator));
            int errorCountModified = _errorIndicators.Count(indicator => modifiedResponse.Contains(indicator));

            // Оценка уверенности
            if (authCountModified > authCountOriginal * 0.7)
            {
                confidence += 0.3;
            }

            if (errorCountModified < errorCountOriginal * 0.5)
            {
                confidence += 0.2;
            }

            if (modifiedResponse.Length > originalResponse.Length * 0.8)
            {
                confidence += 0.1;
            }

            // Проверка на персональные данные
            foreach (var pattern in _personalDataPatterns)
            {
                if (Regex.IsMatch(modifiedResponse, pattern, RegexOptions.IgnoreCase))
                {
                    confidence += 0.2;
                    break;
                }
            }

            // Дополнительные проверки для специфических типов тестов
            if (testType.Contains("json") || testType.Contains("globbing"))
            {
                // Проверка на изменения в структуре JSON
                try
                {
                    var originalJson = JObject.Parse(originalResponse);
                    var modifiedJson = JObject.Parse(modifiedResponse);

                    if (modifiedJson.Count > originalJson.Count * 0.8)
                    {
                        confidence += 0.2;
                    }
                }
                catch
                {
                    // Не JSON ответ
                }
            }

            bool isVulnerable = confidence >= _sensitivity;
            details = $"Confidence: {confidence:F2}, Auth indicators: {authCountModified}, Error indicators: {errorCountModified}, Test type: {testType}";

            return (isVulnerable, confidence, details);
        }

        // Улучшенная генерация тестовых значений с поддержкой всех техник из статьи
        private List<(string value, string testType)> GenerateAdvancedTestValues(string originalValue, string paramName)
        {
            var testValues = new List<(string value, string testType)>();

            // 1. Базовые тесты (числовые и строковые)
            if (int.TryParse(originalValue, out int num))
            {
                testValues.AddRange(new List<(string, string)>
                {
                    ((num + 1).ToString(), "basic_numeric"),
                    ((num - 1).ToString(), "basic_numeric"),
                    ((num + 10).ToString(), "basic_numeric"),
                    ((num - 10).ToString(), "basic_numeric"),
                    ("1", "basic_numeric"),
                    ("0", "basic_numeric"),
                    ("999999", "basic_numeric"),
                    ("-1", "negative_number"),
                    ((num * -1).ToString(), "negative_number"),
                    ((num + 0.5).ToString(), "decimal_number"),
                    ("000" + num.ToString(), "zero_padding"),
                    ("1234,1235", "comma_separated")
                });
            }
            else
            {
                // Проверка на UUID или хеш
                bool isUuid = Guid.TryParse(originalValue, out _) ||
                              Regex.IsMatch(originalValue, @"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$") ||
                              Regex.IsMatch(originalValue, @"^[a-fA-F0-9]{32}$");

                if (isUuid)
                {
                    // Для UUID пробуем другие известные ID
                    testValues.AddRange(_discoveredIds.Take(5).Select(id => (id, "uuid_enumeration")));
                }
                else
                {
                    // Обычные строковые тесты
                    testValues.AddRange(new List<(string, string)>
                    {
                        ($"{originalValue}_test", "string_append"),
                        ("admin", "common_value"),
                        ("test", "common_value"),
                        ("1", "string_to_number"),
                        ("0", "string_to_number"),
                        (originalValue.ToLower(), "case_change"),
                        (originalValue.ToUpper(), "case_change"),
                        ("*", "wildcard"),
                        ("%", "wildcard"),
                        ("true", "boolean"),
                        ("false", "boolean")
                    });
                }
            }

            // 2. Тесты для ключевых слов "current" и "me"
            if (paramName.ToLower() == "user" || paramName.ToLower().Contains("id"))
            {
                if (originalValue.ToLower() == "current" || originalValue.ToLower() == "me")
                {
                    testValues.AddRange(new List<(string, string)>
                    {
                        ("1", "keyword_replacement"),
                        ("2", "keyword_replacement"),
                        ("100", "keyword_replacement"),
                        ("admin", "keyword_replacement"),
                        (Guid.NewGuid().ToString(), "keyword_replacement")
                    });
                }
            }

            // 3. Тесты для JSON globbing
            testValues.AddRange(new List<(string, string)>
            {
                ("[1234,1235]", "json_array"),
                ("[1234,1235,1236]", "json_array"),
                ("true", "json_boolean"),
                ("false", "json_boolean"),
                ("*", "json_wildcard"),
                ("%", "json_wildcard"),
                ("00001235", "json_zero_padding"),
                ("-1", "json_negative"),
                ("1235.0", "json_decimal"),
                ("\"1234,1235\"", "json_string_array")
            });

            // 4. Удаление дубликатов и пустых значений
            return testValues
                .Distinct()
                .Where(v => !string.IsNullOrWhiteSpace(v.value))
                .ToList();
        }

        // Новый метод для тестирования различных HTTP методов
        private async Task<List<ScanResult>> TestHttpMethodVariationsAsync(string url, NameValueCollection queryParams, string paramName, string originalValue)
        {
            var results = new List<ScanResult>();
            var methodsToTest = new[] { HttpMethod.Post, HttpMethod.Put, HttpMethod.Delete, HttpMethod.Patch };

            foreach (var method in methodsToTest)
            {
                try
                {
                    // Создание модифицированного URL
                    var modifiedParams = new NameValueCollection(queryParams);
                    modifiedParams[paramName] = "1"; // Используем базовое тестовое значение

                    string modifiedQuery = modifiedParams.ToString();
                    string modifiedUrl = $"{new Uri(url).GetLeftPart(UriPartial.Path)}?{modifiedQuery}";

                    if (_testedUrls.ContainsKey(modifiedUrl + method.Method))
                        continue;

                    _testedUrls[modifiedUrl + method.Method] = true;

                    // Создание запроса с разными методами
                    var request = new HttpRequestMessage(method, modifiedUrl);

                    // Для POST/PUT добавляем тело запроса
                    if (method == HttpMethod.Post || method == HttpMethod.Put)
                    {
                        var body = new Dictionary<string, string>
                        {
                            { paramName, "1" }
                        };
                        request.Content = new StringContent(JsonConvert.SerializeObject(body), Encoding.UTF8, "application/json");
                    }

                    var response = await _httpClient.SendAsync(request);
                    var content = await response.Content.ReadAsStringAsync();

                    // Анализ результатов
                    var originalResponse = await _httpClient.GetAsync(url);
                    var originalContent = await originalResponse.Content.ReadAsStringAsync();

                    var (isVulnerable, confidence, details) = AnalyzeResponse(
                        originalContent, content,
                        originalResponse.StatusCode, response.StatusCode,
                        $"http_method_{method.Method.ToLower()}"
                    );

                    if (isVulnerable)
                    {
                        string riskLevel = confidence > 0.9 ? "HIGH" :
                                          confidence > 0.7 ? "MEDIUM" : "LOW";

                        results.Add(new ScanResult
                        {
                            Url = url,
                            ModifiedUrl = modifiedUrl,
                            Parameter = paramName,
                            OriginalValue = originalValue,
                            TestValue = "1",
                            TestType = $"http_method_{method.Method.ToLower()}",
                            HttpMethod = method.Method,
                            IsVulnerable = isVulnerable,
                            Confidence = confidence,
                            RiskLevel = riskLevel,
                            Details = details,
                            OriginalStatusCode = (int)originalResponse.StatusCode,
                            ModifiedStatusCode = (int)response.StatusCode,
                            OriginalContentLength = originalContent.Length,
                            ModifiedContentLength = content.Length,
                            ScanTime = DateTime.Now
                        });
                    }
                }
                catch (Exception ex)
                {
                    AnsiConsole.WriteLine($"[yellow]Warning testing {method.Method} on {url}: {ex.Message}[/]");
                }
            }

            return results;
        }

        // Новый метод для тестирования с разными Content-Type заголовками
        private async Task<List<ScanResult>> TestContentTypeVariationsAsync(string url, NameValueCollection queryParams, string paramName, string originalValue)
        {
            var results = new List<ScanResult>();
            var contentTypes = new[] {
                "application/json",
                "application/x-www-form-urlencoded",
                "text/xml",
                "application/xml",
                "multipart/form-data"
            };

            foreach (var contentType in contentTypes)
            {
                try
                {
                    var modifiedParams = new NameValueCollection(queryParams);
                    modifiedParams[paramName] = "1";

                    string modifiedQuery = modifiedParams.ToString();
                    string modifiedUrl = $"{new Uri(url).GetLeftPart(UriPartial.Path)}?{modifiedQuery}";

                    if (_testedUrls.ContainsKey(modifiedUrl + contentType))
                        continue;

                    _testedUrls[modifiedUrl + contentType] = true;

                    var request = new HttpRequestMessage(HttpMethod.Post, modifiedUrl);
                    request.Content = new StringContent($"{{{paramName}}}:1", Encoding.UTF8, contentType);
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                    var response = await _httpClient.SendAsync(request);
                    var content = await response.Content.ReadAsStringAsync();

                    var originalResponse = await _httpClient.GetAsync(url);
                    var originalContent = await originalResponse.Content.ReadAsStringAsync();

                    var (isVulnerable, confidence, details) = AnalyzeResponse(
                        originalContent, content,
                        originalResponse.StatusCode, response.StatusCode,
                        $"content_type_{contentType.Replace("/", "_")}"
                    );

                    if (isVulnerable)
                    {
                        string riskLevel = confidence > 0.9 ? "HIGH" :
                                          confidence > 0.7 ? "MEDIUM" : "LOW";

                        results.Add(new ScanResult
                        {
                            Url = url,
                            ModifiedUrl = modifiedUrl,
                            Parameter = paramName,
                            OriginalValue = originalValue,
                            TestValue = "1",
                            TestType = $"content_type_{contentType.Replace("/", "_")}",
                            ContentType = contentType,
                            HttpMethod = "POST",
                            IsVulnerable = isVulnerable,
                            Confidence = confidence,
                            RiskLevel = riskLevel,
                            Details = details,
                            OriginalStatusCode = (int)originalResponse.StatusCode,
                            ModifiedStatusCode = (int)response.StatusCode,
                            OriginalContentLength = originalContent.Length,
                            ModifiedContentLength = content.Length,
                            ScanTime = DateTime.Now
                        });
                    }
                }
                catch (Exception ex)
                {
                    AnsiConsole.WriteLine($"[yellow]Warning testing content type {contentType} on {url}: {ex.Message}[/]");
                }
            }

            return results;
        }

        // Новый метод для тестирования устаревших версий API
        private async Task<List<ScanResult>> TestApiVersionVariationsAsync(string url)
        {
            var results = new List<ScanResult>();
            var uri = new Uri(url);

            foreach (var version in _apiVersions)
            {
                try
                {
                    // Заменяем версию API в URL
                    string path = uri.AbsolutePath;
                    string newPath = "";

                    if (path.Contains("/api/"))
                    {
                        var parts = path.Split('/');
                        for (int i = 0; i < parts.Length; i++)
                        {
                            if (parts[i] == "api" && i + 1 < parts.Length && !string.IsNullOrEmpty(parts[i + 1]))
                            {
                                parts[i + 1] = version;
                                break;
                            }
                        }
                        newPath = string.Join("/", parts);
                    }
                    else if (path.StartsWith("/v") || path.StartsWith("/V"))
                    {
                        // Заменяем текущую версию на другую
                        newPath = Regex.Replace(path, @"/v\d+", $"/{version}", RegexOptions.IgnoreCase);
                    }

                    if (!string.IsNullOrEmpty(newPath) && newPath != path)
                    {
                        string newUrl = $"{uri.Scheme}://{uri.Host}{newPath}{uri.Query}";

                        if (_testedUrls.ContainsKey(newUrl))
                            continue;

                        _testedUrls[newUrl] = true;

                        var response = await _httpClient.GetAsync(newUrl);
                        var content = await response.Content.ReadAsStringAsync();

                        // Сравниваем с оригинальным ответом
                        var originalResponse = await _httpClient.GetAsync(url);
                        var originalContent = await originalResponse.Content.ReadAsStringAsync();

                        var (isVulnerable, confidence, details) = AnalyzeResponse(
                            originalContent, content,
                            originalResponse.StatusCode, response.StatusCode,
                            $"api_version_{version}"
                        );

                        if (isVulnerable && response.StatusCode == HttpStatusCode.OK)
                        {
                            string riskLevel = confidence > 0.9 ? "HIGH" :
                                              confidence > 0.7 ? "MEDIUM" : "LOW";

                            results.Add(new ScanResult
                            {
                                Url = url,
                                ModifiedUrl = newUrl,
                                Parameter = "api_version",
                                OriginalValue = path,
                                TestValue = newPath,
                                TestType = $"api_version_{version}",
                                IsVulnerable = isVulnerable,
                                Confidence = confidence,
                                RiskLevel = riskLevel,
                                Details = details,
                                OriginalStatusCode = (int)originalResponse.StatusCode,
                                ModifiedStatusCode = (int)response.StatusCode,
                                OriginalContentLength = originalContent.Length,
                                ModifiedContentLength = content.Length,
                                ScanTime = DateTime.Now
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    AnsiConsole.WriteLine($"[yellow]Warning testing API version {version} on {url}: {ex.Message}[/]");
                }
            }

            return results;
        }

        // Новый метод для тестирования параметр польюшена (parameter pollution)
        private async Task<List<ScanResult>> TestParameterPollutionAsync(string url, NameValueCollection queryParams, string paramName, string originalValue)
        {
            var results = new List<ScanResult>();

            try
            {
                // Создаем URL с дублированным параметром
                var pollutedParams = new NameValueCollection(queryParams);
                pollutedParams.Add(paramName, "1"); // Добавляем второй параметр с тем же именем

                string pollutedQuery = pollutedParams.ToString();
                string pollutedUrl = $"{new Uri(url).GetLeftPart(UriPartial.Path)}?{pollutedQuery}";

                if (_testedUrls.ContainsKey(pollutedUrl))
                    return results;

                _testedUrls[pollutedUrl] = true;

                var response = await _httpClient.GetAsync(pollutedUrl);
                var content = await response.Content.ReadAsStringAsync();

                var originalResponse = await _httpClient.GetAsync(url);
                var originalContent = await originalResponse.Content.ReadAsStringAsync();

                var (isVulnerable, confidence, details) = AnalyzeResponse(
                    originalContent, content,
                    originalResponse.StatusCode, response.StatusCode,
                    "parameter_pollution"
                );

                if (isVulnerable)
                {
                    string riskLevel = confidence > 0.9 ? "HIGH" :
                                      confidence > 0.7 ? "MEDIUM" : "LOW";

                    results.Add(new ScanResult
                    {
                        Url = url,
                        ModifiedUrl = pollutedUrl,
                        Parameter = paramName,
                        OriginalValue = originalValue,
                        TestValue = "1",
                        TestType = "parameter_pollution",
                        IsVulnerable = isVulnerable,
                        Confidence = confidence,
                        RiskLevel = riskLevel,
                        Details = details,
                        OriginalStatusCode = (int)originalResponse.StatusCode,
                        ModifiedStatusCode = (int)response.StatusCode,
                        OriginalContentLength = originalContent.Length,
                        ModifiedContentLength = content.Length,
                        ScanTime = DateTime.Now
                    });
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteLine($"[yellow]Warning testing parameter pollution on {url}: {ex.Message}[/]");
            }

            return results;
        }

        // Новый метод для обнаружения ID из ответов (для UUID)
        private async Task DiscoverIdsFromResponseAsync(string responseContent)
        {
            try
            {
                // Поиск UUID в ответе
                var uuidMatches = Regex.Matches(responseContent, @"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}", RegexOptions.IgnoreCase);
                foreach (Match match in uuidMatches)
                {
                    if (!_discoveredIds.Contains(match.Value))
                    {
                        _discoveredIds.Add(match.Value);
                    }
                }

                // Поиск числовых ID
                var idMatches = Regex.Matches(responseContent, @"\""(id|user_id|document_id|record_id|profile_id)\""\s*:\s*(\d+)", RegexOptions.IgnoreCase);
                foreach (Match match in idMatches)
                {
                    if (match.Groups.Count > 2)
                    {
                        string idValue = match.Groups[2].Value;
                        if (!_discoveredIds.Contains(idValue))
                        {
                            _discoveredIds.Add(idValue);
                        }
                    }
                }

                // Поиск ID в URL
                var urlMatches = Regex.Matches(responseContent, @"https?://[^\s\""]+/api/[^\s\""]*[/=](\d+|[\w\-]{8,})", RegexOptions.IgnoreCase);
                foreach (Match match in urlMatches)
                {
                    if (match.Groups.Count > 1)
                    {
                        string idValue = match.Groups[1].Value;
                        if (idValue.Length <= 32 && !_discoveredIds.Contains(idValue))
                        {
                            _discoveredIds.Add(idValue);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteLine($"[yellow]Error discovering IDs: {ex.Message}[/]");
            }
        }

        // Основной метод тестирования с поддержкой всех техник
        private async Task<List<ScanResult>> TestUrlForAdvancedIdorAsync(string url)
        {
            if (_testedUrls.ContainsKey(url))
            {
                return new List<ScanResult>();
            }

            _testedUrls[url] = true;
            var results = new List<ScanResult>();

            try
            {
                var uri = new Uri(url);
                var queryParams = HttpUtility.ParseQueryString(uri.Query);

                if (queryParams.Count == 0)
                {
                    return results;
                }

                // Получение оригинального ответа для анализа и поиска ID
                var originalResponse = await _httpClient.GetAsync(url);
                var originalContent = await originalResponse.Content.ReadAsStringAsync();

                // Обнаружение ID из ответа
                await DiscoverIdsFromResponseAsync(originalContent);

                // Тестирование каждого параметра
                foreach (string paramName in queryParams.AllKeys)
                {
                    if (string.IsNullOrEmpty(paramName) || !queryParams[paramName].Any())
                        continue;

                    string originalValue = queryParams[paramName];

                    // Проверка, является ли параметр потенциальным кандидатом для IDOR
                    bool isCandidate = _parameterPatterns.Any(pattern =>
                        paramName.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0);

                    if (!isCandidate && !_parameterPatterns.Contains(paramName.ToLower()))
                    {
                        continue;
                    }

                    // 1. Базовое тестирование
                    var testValues = GenerateAdvancedTestValues(originalValue, paramName);

                    foreach (var (testValue, testType) in testValues)
                    {
                        // Создание модифицированного URL
                        var modifiedParams = new NameValueCollection(queryParams);
                        modifiedParams[paramName] = testValue;

                        string modifiedQuery = modifiedParams.ToString();
                        string modifiedUrl = $"{uri.GetLeftPart(UriPartial.Path)}?{modifiedQuery}";

                        if (_testedUrls.ContainsKey(modifiedUrl))
                        {
                            continue;
                        }

                        _testedUrls[modifiedUrl] = true;

                        try
                        {
                            // Задержка для избежания блокировки
                            await Task.Delay(new Random().Next(100, 500));

                            var modifiedResponse = await _httpClient.GetAsync(modifiedUrl);
                            var modifiedContent = await modifiedResponse.Content.ReadAsStringAsync();

                            // Анализ результатов
                            var (isVulnerable, confidence, details) = AnalyzeResponse(
                                originalContent, modifiedContent,
                                originalResponse.StatusCode, modifiedResponse.StatusCode,
                                testType
                            );

                            if (isVulnerable)
                            {
                                string riskLevel = confidence > 0.9 ? "HIGH" :
                                                  confidence > 0.7 ? "MEDIUM" : "LOW";

                                results.Add(new ScanResult
                                {
                                    Url = url,
                                    ModifiedUrl = modifiedUrl,
                                    Parameter = paramName,
                                    OriginalValue = originalValue,
                                    TestValue = testValue,
                                    TestType = testType,
                                    HttpMethod = "GET",
                                    IsVulnerable = isVulnerable,
                                    Confidence = confidence,
                                    RiskLevel = riskLevel,
                                    Details = details,
                                    OriginalStatusCode = (int)originalResponse.StatusCode,
                                    ModifiedStatusCode = (int)modifiedResponse.StatusCode,
                                    OriginalContentLength = originalContent.Length,
                                    ModifiedContentLength = modifiedContent.Length,
                                    ScanTime = DateTime.Now
                                });
                            }
                        }
                        catch (Exception ex)
                        {
                            AnsiConsole.WriteLine($"[red]Error testing {modifiedUrl}: {ex.Message}[/]");
                            continue;
                        }
                    }

                    // 2. Тестирование параметр польюшена
                    var pollutionResults = await TestParameterPollutionAsync(url, queryParams, paramName, originalValue);
                    results.AddRange(pollutionResults);

                    // 3. Тестирование различных HTTP методов
                    var methodResults = await TestHttpMethodVariationsAsync(url, queryParams, paramName, originalValue);
                    results.AddRange(methodResults);

                    // 4. Тестирование различных Content-Type
                    var contentTypeResults = await TestContentTypeVariationsAsync(url, queryParams, paramName, originalValue);
                    results.AddRange(contentTypeResults);
                }

                // 5. Тестирование устаревших версий API
                var versionResults = await TestApiVersionVariationsAsync(url);
                results.AddRange(versionResults);

            }
            catch (Exception ex)
            {
                AnsiConsole.WriteLine($"[red]Error analyzing {url}: {ex.Message}[/]");
            }

            return results;
        }

        // Дополнительный метод для поиска IDOR в JSON телах запросов
        private async Task<List<ScanResult>> TestJsonEndpointsAsync(string url)
        {
            var results = new List<ScanResult>();

            try
            {
                // Проверяем, является ли это JSON API эндпоинтом
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var response = await _httpClient.SendAsync(request);
                if (response.Content.Headers.ContentType?.MediaType != "application/json")
                {
                    return results;
                }

                var jsonContent = await response.Content.ReadAsStringAsync();

                // Пытаемся найти ID в JSON структуре
                try
                {
                    var json = JObject.Parse(jsonContent);

                    // Поиск полей с ID
                    var idFields = json.Descendants()
                        .OfType<JProperty>()
                        .Where(p => p.Name.ToLower().Contains("id") ||
                                   p.Name.ToLower().Contains("user") ||
                                   p.Name.ToLower().Contains("record") ||
                                   p.Name.ToLower().Contains("document"));

                    foreach (var field in idFields)
                    {
                        if (field.Value.Type == JTokenType.String || field.Value.Type == JTokenType.Integer)
                        {
                            string originalValue = field.Value.ToString();
                            string fieldName = field.Name;

                            // Генерация тестовых значений
                            var testValues = GenerateAdvancedTestValues(originalValue, fieldName);

                            foreach (var (testValue, testType) in testValues)
                            {
                                try
                                {
                                    // Создание модифицированного JSON
                                    var modifiedJson = (JObject)json.DeepClone();
                                    modifiedJson[fieldName] = testValue;

                                    // Отправка POST запроса с модифицированным JSON
                                    var postRequest = new HttpRequestMessage(HttpMethod.Post, url);
                                    postRequest.Content = new StringContent(modifiedJson.ToString(), Encoding.UTF8, "application/json");
                                    postRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                                    var postResponse = await _httpClient.SendAsync(postRequest);
                                    var postContent = await postResponse.Content.ReadAsStringAsync();

                                    // Анализ результатов
                                    var (isVulnerable, confidence, details) = AnalyzeResponse(
                                        jsonContent, postContent,
                                        response.StatusCode, postResponse.StatusCode,
                                        $"json_body_{testType}"
                                    );

                                    if (isVulnerable)
                                    {
                                        string riskLevel = confidence > 0.9 ? "HIGH" :
                                                          confidence > 0.7 ? "MEDIUM" : "LOW";

                                        results.Add(new ScanResult
                                        {
                                            Url = url,
                                            ModifiedUrl = url,
                                            Parameter = fieldName,
                                            OriginalValue = originalValue,
                                            TestValue = testValue,
                                            TestType = $"json_body_{testType}",
                                            HttpMethod = "POST",
                                            ContentType = "application/json",
                                            IsVulnerable = isVulnerable,
                                            Confidence = confidence,
                                            RiskLevel = riskLevel,
                                            Details = details,
                                            OriginalStatusCode = (int)response.StatusCode,
                                            ModifiedStatusCode = (int)postResponse.StatusCode,
                                            OriginalContentLength = jsonContent.Length,
                                            ModifiedContentLength = postContent.Length,
                                            ScanTime = DateTime.Now
                                        });
                                    }
                                }
                                catch (Exception ex)
                                {
                                    AnsiConsole.WriteLine($"[yellow]Warning testing JSON field {fieldName}: {ex.Message}[/]");
                                }
                            }
                        }
                    }
                }
                catch
                {
                    // Не удалось распарсить JSON
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteLine($"[yellow]Error testing JSON endpoint {url}: {ex.Message}[/]");
            }

            return results;
        }

        private async Task<List<string>> CrawlWebsiteAsync(string baseUrl, int maxPages = 20)
        {
            var urlsToScan = new ConcurrentQueue<string>();
            var scannedUrls = new ConcurrentDictionary<string, bool>();
            var foundUrls = new ConcurrentBag<string>();

            urlsToScan.Enqueue(baseUrl);
            foundUrls.Add(baseUrl);

            while (urlsToScan.Count > 0 && scannedUrls.Count < maxPages)
            {
                if (!urlsToScan.TryDequeue(out string currentUrl))
                    continue;

                if (scannedUrls.ContainsKey(currentUrl))
                    continue;

                scannedUrls[currentUrl] = true;

                try
                {
                    HttpResponseMessage response = await _httpClient.GetAsync(currentUrl);
                    string content = await response.Content.ReadAsStringAsync();

                    // Обнаружение ID из ответа
                    await DiscoverIdsFromResponseAsync(content);

                    // Парсинг HTML для поиска ссылок
                    var htmlDoc = new HtmlDocument();
                    htmlDoc.LoadHtml(content);

                    var links = htmlDoc.DocumentNode.SelectNodes("//a[@href]");
                    if (links != null)
                    {
                        foreach (var link in links)
                        {
                            string href = link.GetAttributeValue("href", "").Trim();
                            if (string.IsNullOrEmpty(href) || href.StartsWith("javascript:") || href.StartsWith("#"))
                                continue;

                            // Абсолютизация URL
                            Uri absoluteUri;
                            if (Uri.TryCreate(href, UriKind.RelativeOrAbsolute, out var tempUri))
                            {
                                if (!tempUri.IsAbsoluteUri)
                                {
                                    absoluteUri = new Uri(new Uri(baseUrl), tempUri);
                                }
                                else
                                {
                                    absoluteUri = tempUri;
                                }

                                // Проверка, что URL принадлежит тому же домену
                                if (absoluteUri.Host == new Uri(baseUrl).Host)
                                {
                                    string absoluteUrl = absoluteUri.ToString();
                                    if (!scannedUrls.ContainsKey(absoluteUrl) && !foundUrls.Contains(absoluteUrl))
                                    {
                                        foundUrls.Add(absoluteUrl);
                                        urlsToScan.Enqueue(absoluteUrl);
                                    }
                                }
                            }
                        }
                    }

                    // Также ищем API эндпоинты
                    var apiMatches = Regex.Matches(content, @"/api/[^\s\""""]+", RegexOptions.IgnoreCase);
                    foreach (Match match in apiMatches)
                    {
                        string apiUrl = $"{new Uri(baseUrl).GetLeftPart(UriPartial.Authority)}{match.Value}";
                        if (!scannedUrls.ContainsKey(apiUrl) && !foundUrls.Contains(apiUrl))
                        {
                            foundUrls.Add(apiUrl);
                            urlsToScan.Enqueue(apiUrl);
                        }
                    }
                }
                catch (Exception ex)
                {
                    AnsiConsole.WriteLine($"[red]Error crawling {currentUrl}: {ex.Message}[/]");
                }
            }

            return foundUrls.Where(u => u.Contains("?") || u.Contains("/api/")).ToList();
        }

        public async Task<List<ScanResult>> ScanAsync(string baseUrl, int maxPages = 20)
        {
            AnsiConsole.WriteLine($"[cyan]Starting advanced IDOR scan for: [bold]{baseUrl}[/][/]");
            AnsiConsole.WriteLine($"[yellow]Using advanced techniques from Habr article: parameter pollution, JSON globbing, HTTP method variations, content-type testing, API version testing[/]");

            // Сбор URL с параметрами и API эндпоинтов
            var urlsToScan = await CrawlWebsiteAsync(baseUrl, maxPages);
            AnsiConsole.WriteLine($"[yellow]Found {urlsToScan.Count} URLs with parameters or API endpoints to scan[/]");

            var semaphore = new SemaphoreSlim(_maxConcurrency);
            var tasks = new List<Task<List<ScanResult>>>();

            foreach (string url in urlsToScan)
            {
                await semaphore.WaitAsync();
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var results = new List<ScanResult>();

                        // Тестирование основных уязвимостей
                        var basicResults = await TestUrlForAdvancedIdorAsync(url);
                        results.AddRange(basicResults);

                        // Тестирование JSON эндпоинтов
                        if (url.Contains("/api/"))
                        {
                            var jsonResults = await TestJsonEndpointsAsync(url);
                            results.AddRange(jsonResults);
                        }

                        return results;
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            try
            {
                var results = await Task.WhenAll(tasks);
                foreach (var result in results)
                {
                    foreach (var scanResult in result)
                    {
                        _results.Add(scanResult);
                    }
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteLine($"[red]Error during scan: {ex.Message}[/]");
            }

            return _results.ToList();
        }

        public void GenerateJsonReport(string outputPath)
        {
            var report = new
            {
                Target = _httpClient.BaseAddress?.ToString(),
                ScanTime = DateTime.Now,
                TotalVulnerabilities = _results.Count,
                Vulnerabilities = _results
            };

            File.WriteAllText(outputPath, JsonConvert.SerializeObject(report, Formatting.Indented));
            AnsiConsole.WriteLine($"[green]JSON report saved to: [bold]{outputPath}[/][/]");
        }

        public void GenerateCsvReport(string outputPath)
        {
            var csvLines = new List<string>
            {
                "RiskLevel,TestType,Url,ModifiedUrl,Parameter,OriginalValue,TestValue,Confidence,Details,OriginalStatus,ModifiedStatus,HttpMethod,ContentType"
            };

            foreach (var result in _results)
            {
                csvLines.Add($"{result.RiskLevel},{result.TestType},{result.Url},{result.ModifiedUrl},{result.Parameter}," +
                            $"{result.OriginalValue},{result.TestValue},{result.Confidence:F2},{result.Details.Replace(",", ";")}," +
                            $"{result.OriginalStatusCode},{result.ModifiedStatusCode},{result.HttpMethod ?? "GET"},{result.ContentType ?? "N/A"}");
            }

            File.WriteAllLines(outputPath, csvLines);
            AnsiConsole.WriteLine($"[green]CSV report saved to: [bold]{outputPath}[/][/]");
        }

        public void GeneratePdfReport(string outputPath)
        {
            // Создание PDF документа
            Document pdfDoc = new Document(PageSize.A4);
            PdfWriter.GetInstance(pdfDoc, new FileStream(outputPath, FileMode.Create));
            pdfDoc.Open();

            // Заголовок
            var titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 18);
            var subtitleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 14);
            var normalFont = FontFactory.GetFont(FontFactory.HELVETICA, 10);
            var highRiskFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 10, BaseColor.RED);
            var mediumRiskFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 10, new BaseColor(255, 165, 0));
            var lowRiskFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 10, BaseColor.GREEN);

            pdfDoc.Add(new iTextSharp.text.Paragraph("ADVANCED IDOR SCAN REPORT", titleFont) { Alignment = Element.ALIGN_CENTER });
            pdfDoc.Add(new iTextSharp.text.Paragraph($"Target: {_httpClient.BaseAddress}", subtitleFont) { Alignment = Element.ALIGN_CENTER });
            pdfDoc.Add(new iTextSharp.text.Paragraph($"Scan Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}", subtitleFont) { Alignment = Element.ALIGN_CENTER });
            pdfDoc.Add(new iTextSharp.text.Paragraph($"Total Vulnerabilities Found: {_results.Count}", subtitleFont) { Alignment = Element.ALIGN_CENTER });
            pdfDoc.Add(new iTextSharp.text.Paragraph(" "));

            pdfDoc.Add(new iTextSharp.text.Paragraph("Advanced techniques used:", subtitleFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- Parameter pollution testing", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- JSON globbing (arrays, booleans, wildcards)", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- HTTP method variations (POST, PUT, DELETE, PATCH)", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- Content-Type header manipulation", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- API version enumeration", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- Static keyword replacement (current, me)", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- UUID and unpredictable ID enumeration", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph(" "));

            // Статистика по уровням риска
            var highRisk = _results.Count(r => r.RiskLevel == "HIGH");
            var mediumRisk = _results.Count(r => r.RiskLevel == "MEDIUM");
            var lowRisk = _results.Count(r => r.RiskLevel == "LOW");

            pdfDoc.Add(new iTextSharp.text.Paragraph($"HIGH RISK: {highRisk} vulnerabilities", highRiskFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph($"MEDIUM RISK: {mediumRisk} vulnerabilities", mediumRiskFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph($"LOW RISK: {lowRisk} vulnerabilities", lowRiskFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph(" "));

            // Статистика по типам тестов
            var testTypes = _results.GroupBy(r => r.TestType)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count);

            pdfDoc.Add(new iTextSharp.text.Paragraph("Vulnerabilities by test type:", subtitleFont));
            foreach (var type in testTypes)
            {
                pdfDoc.Add(new iTextSharp.text.Paragraph($"{type.Type}: {type.Count}", normalFont));
            }
            pdfDoc.Add(new iTextSharp.text.Paragraph(" "));

            // Детальные результаты
            foreach (var result in _results)
            {
                var riskFont = result.RiskLevel == "HIGH" ? highRiskFont :
                              result.RiskLevel == "MEDIUM" ? mediumRiskFont : lowRiskFont;

                pdfDoc.Add(new iTextSharp.text.Paragraph($"Risk Level: {result.RiskLevel} ({result.Confidence:F2} confidence)", riskFont));
                pdfDoc.Add(new iTextSharp.text.Paragraph($"Test Type: {result.TestType}", normalFont));
                pdfDoc.Add(new iTextSharp.text.Paragraph($"Vulnerable URL: {result.Url}", normalFont));
                pdfDoc.Add(new iTextSharp.text.Paragraph($"Modified URL: {result.ModifiedUrl}", normalFont));
                pdfDoc.Add(new iTextSharp.text.Paragraph($"Parameter: {result.Parameter}", normalFont));
                pdfDoc.Add(new iTextSharp.text.Paragraph($"Original Value: {result.OriginalValue}", normalFont));
                pdfDoc.Add(new iTextSharp.text.Paragraph($"Test Value: {result.TestValue}", normalFont));
                pdfDoc.Add(new iTextSharp.text.Paragraph($"HTTP Method: {result.HttpMethod ?? "GET"}", normalFont));
                pdfDoc.Add(new iTextSharp.text.Paragraph($"Content Type: {result.ContentType ?? "N/A"}", normalFont));
                pdfDoc.Add(new iTextSharp.text.Paragraph($"Status Codes: {result.OriginalStatusCode} -> {result.ModifiedStatusCode}", normalFont));
                pdfDoc.Add(new iTextSharp.text.Paragraph($"Content Lengths: {result.OriginalContentLength} -> {result.ModifiedContentLength}", normalFont));
                pdfDoc.Add(new iTextSharp.text.Paragraph($"Details: {result.Details}", normalFont));
                pdfDoc.Add(new iTextSharp.text.Paragraph(new string('-', 50)));
                pdfDoc.Add(new iTextSharp.text.Paragraph(" "));
            }

            // Рекомендации
            pdfDoc.Add(new iTextSharp.text.Paragraph("REMEDIATION RECOMMENDATIONS", subtitleFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph(" "));
            pdfDoc.Add(new iTextSharp.text.Paragraph("1. Implement proper access control checks for all sensitive resources", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("2. Use indirect reference maps instead of direct object references", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("3. Implement role-based access control (RBAC) for all user operations", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("4. Validate all user input and implement proper authorization checks", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("5. Use UUIDs instead of sequential IDs for sensitive resources", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("6. Implement logging and monitoring for unauthorized access attempts", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("7. Test all HTTP methods and content types for access control bypass", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("8. Regularly audit API versions and disable old, insecure versions", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("9. Implement proper validation for JSON data structures", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("10. Use parameter binding and strict type checking to prevent parameter pollution", normalFont));

            pdfDoc.Close();
            AnsiConsole.WriteLine($"[green]PDF report saved to: [bold]{outputPath}[/][/]");
        }
    }

}
