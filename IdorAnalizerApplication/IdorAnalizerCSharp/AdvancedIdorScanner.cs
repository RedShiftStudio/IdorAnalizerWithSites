using CommandLine;
using HtmlAgilityPack;
using iTextSharp.text;
using iTextSharp.text.pdf;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Spectre.Console;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace IdorAnalizerCSharp
{
    public class AdvancedIdorScanner
    {
        private readonly HttpClient _httpClient;
        private readonly List<string> _parameterPatterns = new List<string>
        {
            "id", "user", "user_id", "doc", "document", "file", "order",
            "profile", "account", "record", "item", "product", "invoice", "transaction",
            "me", "current", "self"
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
            "unauthorized", "not found", "does not exist", "permission error"
        };

        private readonly List<string> _personalDataPatterns = new List<string>
        {
            @"\b[\w\.-]+@[\w\.-]+\.\w+\b",  // email
            @"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  // phone
            @"\b\d{16}\b",  // credit card (упрощенный)
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
        private readonly List<string> _sensitiveEndpoints = new List<string> { "profile", "document", "user", "account", "api" };
        private readonly Random _random = new Random();

        public AdvancedIdorScanner(HttpClient httpClient, int maxConcurrency = 5, double sensitivity = 0.7, int timeoutSeconds = 10)
        {
            _httpClient = httpClient;
            _maxConcurrency = maxConcurrency;
            _sensitivity = sensitivity;
            _timeoutSeconds = timeoutSeconds;
        }

        private (bool isVulnerable, double confidence, string details) AnalyzeResponse(string originalResponse, string modifiedResponse,
            HttpStatusCode originalStatus, HttpStatusCode modifiedStatus, string testType = "basic")
        {
            double confidence = 0.2; // Базовая уверенность
            string details = "";
            bool hasPersonalData = false;
            bool isSensitiveResponse = false;

            // Анализ статус кодов с эвристиками
            if ((int)modifiedStatus != (int)originalStatus)
            {
                if ((int)modifiedStatus == 200 && ((int)originalStatus == 403 || (int)originalStatus == 404))
                {
                    confidence += 0.4;
                    details += "✅ Доступ получен для запрещенного ресурса; ";
                }
                else if (((int)modifiedStatus == 403 || (int)modifiedStatus == 404) && (int)originalStatus == 200)
                {
                    confidence -= 0.3;
                    details += "❌ Доступ запрещен как ожидалось; ";
                }
                else if ((int)modifiedStatus == 500)
                {
                    confidence += 0.2;
                    details += "⚠️ Ошибка сервера при изменении параметра; ";
                }
                else if ((int)modifiedStatus == 200 && (int)originalStatus == 401)
                {
                    confidence += 0.5;
                    details += "🔥 Обход аутентификации; ";
                    isSensitiveResponse = true;
                }
            }
            else if ((int)modifiedStatus == 200 && (int)originalStatus == 200)
            {
                confidence += 0.1;
                details += "ℹ️ Оба запроса успешны; ";
            }

            // Анализ содержимого в нижнем регистре
            string originalResponseLower = originalResponse.ToLower();
            string modifiedResponseLower = modifiedResponse.ToLower();

            // Проверка авторизованного контента
            int authCountOriginal = _authIndicators.Count(indicator => originalResponseLower.Contains(indicator));
            int authCountModified = _authIndicators.Count(indicator => modifiedResponseLower.Contains(indicator));

            // Проверка ошибок доступа
            int errorCountOriginal = _errorIndicators.Count(indicator => originalResponseLower.Contains(indicator));
            int errorCountModified = _errorIndicators.Count(indicator => modifiedResponseLower.Contains(indicator));

            // Анализ авторизованного контента
            if (authCountModified > 0)
            {
                if (authCountModified > authCountOriginal)
                {
                    confidence += Math.Min(0.3, authCountModified * 0.08);
                    details += $"✅ Авторизованный контент обнаружен ({authCountModified} индикаторов); ";
                    isSensitiveResponse = true;
                }
                else
                {
                    confidence += 0.1;
                    details += $"ℹ️ Авторизованный контент обнаружен ({authCountModified} индикаторов); ";
                }
            }

            // Анализ ошибок доступа
            if (errorCountModified > 0)
            {
                if (errorCountModified > errorCountOriginal)
                {
                    confidence -= Math.Min(0.4, errorCountModified * 0.1);
                    details += $"❌ Обнаружены ошибки доступа ({errorCountModified} индикаторов); ";
                }
                else
                {
                    confidence -= 0.05;
                    details += $"⚠️ Обнаружены ошибки доступа ({errorCountModified} индикаторов); ";
                }
            }

            // Анализ длины ответа
            double lengthRatio = modifiedResponse.Length > 0 ?
                (double)originalResponse.Length / modifiedResponse.Length : 0;

            if (lengthRatio > 0.8 && lengthRatio < 1.2)
            {
                confidence += 0.2;
                details += $"✅ Длина ответов очень схожа (коэффициент: {lengthRatio:F2}); ";
            }
            else if (lengthRatio > 0.6 && lengthRatio < 1.5)
            {
                confidence += 0.1;
                details += $"ℹ️ Длина ответов умеренно схожа (коэффициент: {lengthRatio:F2}); ";
            }
            else if (lengthRatio < 0.4 || lengthRatio > 2.0)
            {
                confidence -= 0.1;
                details += $"⚠️ Длина ответов значительно различается (коэффициент: {lengthRatio:F2}); ";
            }

            // Проверка на персональные данные
            foreach (var pattern in _personalDataPatterns)
            {
                if (Regex.IsMatch(modifiedResponse, pattern, RegexOptions.IgnoreCase))
                {
                    confidence += 0.4;
                    hasPersonalData = true;
                    details += "🔥 Обнаружены персональные данные; ";
                    isSensitiveResponse = true;
                    break;
                }
            }

            // Проверка специфических индикаторов для разных типов запросов
            if (testType.Contains("json") || testType.Contains("globbing"))
            {
                try
                {
                    var originalJson = JObject.Parse(originalResponse);
                    var modifiedJson = JObject.Parse(modifiedResponse);

                    // Сравнение количества полей
                    if (Math.Abs(originalJson.Count - modifiedJson.Count) <= 2)
                    {
                        confidence += 0.1;
                        details += $"✅ Структура JSON схожа; ";
                    }

                    // Проверка на наличие данных в обоих ответах
                    if (modifiedJson.HasValues && originalJson.HasValues)
                    {
                        confidence += 0.1;
                        details += $"✅ Оба ответа содержат данные; ";
                    }
                }
                catch
                {
                    // Не JSON ответ
                }
            }

            // Дополнительное повышение уверенности для чувствительных эндпоинтов
            if (isSensitiveResponse && hasPersonalData)
            {
                confidence += 0.2;
            }

            bool isVulnerable = confidence >= _sensitivity;

            // Создание информативного сообщения с деталями
            string dataSample = ExtractDataSample(modifiedResponse);
            if (!string.IsNullOrEmpty(dataSample))
            {
                details += $"🔍 Пример данных: {dataSample.Substring(0, Math.Min(50, dataSample.Length))}...";
            }

            details = $"Уровень уверенности: {confidence:F2}, Детали: {details.TrimEnd(';')} Тип теста: {testType}";

            // Ограничение confidence в диапазоне [0, 1]
            confidence = Math.Max(0, Math.Min(1, confidence));

            return (isVulnerable, confidence, details);
        }

        private string ExtractDataSample(string responseContent)
        {
            try
            {
                // Попытка распарсить JSON
                var json = JObject.Parse(responseContent);
                // ИСПРАВЛЕНИЕ: Используем JsonConvert.SerializeObject вместо json.ToString
                return $"JSON: {JsonConvert.SerializeObject(json, Formatting.None, new JsonSerializerSettings { MaxDepth = 2, ReferenceLoopHandling = ReferenceLoopHandling.Ignore })}";
            }
            catch
            {
                // Поиск email, телефонов для примера
                var emailMatch = Regex.Match(responseContent, @"\b[\w\.-]+@[\w\.-]+\.\w+\b");
                if (emailMatch.Success)
                    return $"Email: {emailMatch.Value}";

                var phoneMatch = Regex.Match(responseContent, @"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b");
                if (phoneMatch.Success)
                    return $"Phone: {phoneMatch.Value}";
            }

            // Возврат первых 100 символов как примера
            return responseContent.Substring(0, Math.Min(100, responseContent.Length));
        }

        private List<(string value, string testType)> GenerateAdvancedTestValues(string originalValue, string paramName, string url)
        {
            var testValues = new List<(string value, string testType)>();
            bool isSensitiveEndpoint = _sensitiveEndpoints.Any(ep => url.ToLower().Contains(ep));
            bool isApiEndpoint = url.ToLower().Contains("api");

            // Базовые тесты (числовые и строковые)
            if (int.TryParse(originalValue, out int num))
            {
                testValues.AddRange(new List<(string, string)>
                {
                    ((num + 1).ToString(), "basic_numeric"),
                    ((num - 1).ToString(), "basic_numeric"),
                    ("1", "basic_numeric"),
                    ("2", "basic_numeric"),
                    ("0", "basic_numeric"),
                    ("999999", "basic_numeric")
                });

                if (isSensitiveEndpoint)
                {
                    testValues.AddRange(new List<(string, string)>
                    {
                        ("-1", "negative_number"),
                        ((num * -1).ToString(), "negative_number"),
                        ((num + 0.5).ToString(), "decimal_number"),
                        ("000" + num.ToString(), "zero_padding")
                    });
                }
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
                    testValues.AddRange(_discoveredIds.Take(2).Select(id => (id, "uuid_enumeration")));
                }
                else
                {
                    // Обычные строковые тесты
                    testValues.AddRange(new List<(string, string)>
                    {
                        ("admin", "common_value"),
                        ("test", "common_value"),
                        (originalValue.ToLower(), "case_change"),
                        (originalValue.ToUpper(), "case_change")
                    });

                    if (isSensitiveEndpoint)
                    {
                        testValues.AddRange(new List<(string, string)>
                        {
                            ("1", "basic_numeric"),
                            ("2", "basic_numeric"),
                            ("0", "basic_numeric"),
                            ("999999", "basic_numeric")
                        });
                    }
                }
            }

            // Удаление дубликатов и пустых значений
            return testValues
                .Distinct()
                .Where(v => !string.IsNullOrWhiteSpace(v.value))
                .Take(8) // Ограничиваем количество тестов для каждого параметра
                .ToList();
        }

        private async Task<List<ScanResult>> TestUrlForAdvancedIdorAsync(string url)
        {
            if (_testedUrls.ContainsKey(url))
            {
                return new List<ScanResult>();
            }

            _testedUrls[url] = true;
            var results = new List<ScanResult>();
            bool isSensitiveEndpoint = _sensitiveEndpoints.Any(ep => url.ToLower().Contains(ep));

            try
            {
                var uri = new Uri(url);
                var queryParams = HttpUtility.ParseQueryString(uri.Query);

                if (queryParams.Count == 0 && !isSensitiveEndpoint)
                {
                    return results;
                }

                // Получение оригинального ответа
                var originalResponse = await _httpClient.GetAsync(url);
                var originalContent = await originalResponse.Content.ReadAsStringAsync();

                // Тестирование только чувствительных эндпоинтов без параметров
                if (queryParams.Count == 0)
                {
                    var sensitiveResults = await TestSensitiveEndpointWithoutParamsAsync(url, originalContent, originalResponse);
                    results.AddRange(sensitiveResults);
                    return results;
                }

                // Обнаружение ID из ответа
                await DiscoverIdsFromResponseAsync(originalContent);

                // Тестирование каждого параметра
                foreach (string paramName in queryParams.AllKeys)
                {
                    if (string.IsNullOrEmpty(paramName) || string.IsNullOrEmpty(queryParams[paramName]))
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
                    var testValues = GenerateAdvancedTestValues(originalValue, paramName, url);

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
                            await Task.Delay(_random.Next(100, 500));

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
                                string riskLevel = confidence > 0.9 ? "CRITICAL" :
                                                  confidence > 0.8 ? "HIGH" :
                                                  confidence > 0.6 ? "MEDIUM" : "LOW";

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
                                    VulnerableDataSample = ExtractDataSample(modifiedContent),
                                    ScanTime = DateTime.Now
                                });
                            }
                        }
                        catch (Exception ex)
                        {
                            AnsiConsole.WriteLine($"[yellow]Warning testing {modifiedUrl}: {ex.Message}[/]");
                        }
                    }

                    // 2. Тестирование HTTP методов для чувствительных эндпоинтов
                    if (isSensitiveEndpoint)
                    {
                        var methodResults = await TestHttpMethodVariationsAsync(url, queryParams, paramName, originalValue);
                        results.AddRange(methodResults);
                    }

                    bool isApiEndpoint = url.ToLower().Contains("api");

                    // 3. Тестирование различных Content-Type для чувствительных эндпоинтов
                    if (isSensitiveEndpoint && isApiEndpoint)
                    {
                        var contentTypeResults = await TestContentTypeVariationsAsync(url, queryParams, paramName, originalValue);
                        results.AddRange(contentTypeResults);
                    }
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteLine($"[red]Error analyzing {url}: {ex.Message}[/]");
            }

            return results;
        }

        private async Task<List<ScanResult>> TestSensitiveEndpointWithoutParamsAsync(string url, string originalContent, HttpResponseMessage originalResponse)
        {
            var results = new List<ScanResult>();
            var testPaths = new List<string> { "1", "2", "admin", "me", "current" };

            var uri = new Uri(url);
            string basePath = uri.GetLeftPart(UriPartial.Path);

            foreach (var testPath in testPaths)
            {
                string testUrl = $"{basePath}/{testPath}";

                if (_testedUrls.ContainsKey(testUrl))
                    continue;

                _testedUrls[testUrl] = true;

                try
                {
                    await Task.Delay(_random.Next(100, 500));
                    var testResponse = await _httpClient.GetAsync(testUrl);
                    var testContent = await testResponse.Content.ReadAsStringAsync();

                    var (isVulnerable, confidence, details) = AnalyzeResponse(
                        originalContent, testContent,
                        originalResponse.StatusCode, testResponse.StatusCode,
                        "path_traversal"
                    );

                    if (isVulnerable)
                    {
                        string riskLevel = confidence > 0.9 ? "CRITICAL" :
                                          confidence > 0.8 ? "HIGH" :
                                          confidence > 0.6 ? "MEDIUM" : "LOW";

                        results.Add(new ScanResult
                        {
                            Url = url,
                            ModifiedUrl = testUrl,
                            Parameter = "path",
                            OriginalValue = "",
                            TestValue = testPath,
                            TestType = "path_traversal",
                            HttpMethod = "GET",
                            IsVulnerable = isVulnerable,
                            Confidence = confidence,
                            RiskLevel = riskLevel,
                            Details = details,
                            OriginalStatusCode = (int)originalResponse.StatusCode,
                            ModifiedStatusCode = (int)testResponse.StatusCode,
                            OriginalContentLength = originalContent.Length,
                            ModifiedContentLength = testContent.Length,
                            VulnerableDataSample = ExtractDataSample(testContent),
                            ScanTime = DateTime.Now
                        });
                    }
                }
                catch (Exception ex)
                {
                    AnsiConsole.WriteLine($"[yellow]Warning testing path {testUrl}: {ex.Message}[/]");
                }
            }

            return results;
        }

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
                    if (match.Groups.Count > 2 && int.TryParse(match.Groups[2].Value, out int idValue))
                    {
                        string idStr = idValue.ToString();
                        if (!_discoveredIds.Contains(idStr))
                        {
                            _discoveredIds.Add(idStr);
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

        private async Task<List<ScanResult>> TestHttpMethodVariationsAsync(string url, NameValueCollection queryParams, string paramName, string originalValue)
        {
            var results = new List<ScanResult>();
            var methodsToTest = new[] { HttpMethod.Post, HttpMethod.Put };

            foreach (var method in methodsToTest)
            {
                try
                {
                    // Создание модифицированного URL
                    var modifiedParams = new NameValueCollection(queryParams);
                    modifiedParams[paramName] = "1";

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

                    // Анализ результатов только если статус 200
                    if ((int)response.StatusCode == 200)
                    {
                        var originalResponse = await _httpClient.GetAsync(url);
                        var originalContent = await originalResponse.Content.ReadAsStringAsync();

                        var (isVulnerable, confidence, details) = AnalyzeResponse(
                            originalContent, content,
                            originalResponse.StatusCode, response.StatusCode,
                            $"http_method_{method.Method.ToLower()}"
                        );

                        if (isVulnerable && confidence > 0.5)
                        {
                            string riskLevel = confidence > 0.9 ? "CRITICAL" :
                                              confidence > 0.8 ? "HIGH" :
                                              confidence > 0.6 ? "MEDIUM" : "LOW";

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
                                VulnerableDataSample = ExtractDataSample(content),
                                ScanTime = DateTime.Now
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    AnsiConsole.WriteLine($"[yellow]Warning testing {method.Method} on {url}: {ex.Message}[/]");
                }
            }

            return results;
        }

        private async Task<List<ScanResult>> TestContentTypeVariationsAsync(string url, NameValueCollection queryParams, string paramName, string originalValue)
        {
            var results = new List<ScanResult>();
            var contentTypes = new[] { "application/json", "application/xml" };

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

                    // Анализ результатов только если статус 200
                    if ((int)response.StatusCode == 200)
                    {
                        var originalResponse = await _httpClient.GetAsync(url);
                        var originalContent = await originalResponse.Content.ReadAsStringAsync();

                        var (isVulnerable, confidence, details) = AnalyzeResponse(
                            originalContent, content,
                            originalResponse.StatusCode, response.StatusCode,
                            $"content_type_{contentType.Replace("/", "_")}"
                        );

                        if (isVulnerable && confidence > 0.5)
                        {
                            string riskLevel = confidence > 0.9 ? "CRITICAL" :
                                              confidence > 0.8 ? "HIGH" :
                                              confidence > 0.6 ? "MEDIUM" : "LOW";

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
                                VulnerableDataSample = ExtractDataSample(content),
                                ScanTime = DateTime.Now
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    AnsiConsole.WriteLine($"[yellow]Warning testing content type {contentType} on {url}: {ex.Message}[/]");
                }
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
                    if (!response.IsSuccessStatusCode)
                        continue;

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
                    var apiMatches = Regex.Matches(content, @"/api/[^\s""]+ ", RegexOptions.IgnoreCase);

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

            // Фильтрация URL для сканирования
            return foundUrls
                .Where(u => u.Contains("?") || u.Contains("/api/") || _sensitiveEndpoints.Any(ep => u.ToLower().Contains(ep)))
                .Distinct()
                .ToList();
        }

        private List<string> GenerateCandidateUrls(string baseUrl)
        {
            var candidateUrls = new List<string>();
            var baseUri = new Uri(baseUrl);

            // Паттерны для IDOR тестирования
            var patterns = new List<string>
            {
                // API эндпоинты
                "/api/v1/users/{id}",
                "/api/v1/profiles/{id}",
                "/api/v1/documents/{id}",
                "/api/v2/users/{id}",
                "/api/v2/profiles/{id}",
                "/api/users/{id}",
                "/api/profiles/{id}",
                
                // Веб-эндпоинты
                "/users/{id}",
                "/profiles/{id}",
                "/documents/{id}",
                "/documents/view?id={id}",
                "/documents?id={id}",
                "/users/profile?id={id}"
            };

            // Тестовые ID
            var testIds = new[] { "1", "2", "100", "999" };

            foreach (var pattern in patterns)
            {
                foreach (var id in testIds)
                {
                    string urlPath = pattern.Replace("{id}", id);
                    string fullUrl = $"{baseUri.Scheme}://{baseUri.Host}{urlPath}";
                    candidateUrls.Add(fullUrl);
                }
            }

            return candidateUrls.Distinct().ToList();
        }

        public async Task<List<ScanResult>> ScanAsync(string baseUrl, int maxPages = 20)
        {
            AnsiConsole.MarkupLine($"[cyan]Starting advanced IDOR scan for: [bold]{baseUrl}[/][/]");
            AnsiConsole.MarkupLine($"[yellow]Using advanced techniques from Habr article: https://habr.com/ru/articles/848116/[/]");

            // Сбор URL с параметрами через краулинг
            var crawledUrls = await CrawlWebsiteAsync(baseUrl, maxPages);
            AnsiConsole.MarkupLine($"[yellow]Found {crawledUrls.Count} URLs during crawling[/]");

            // Генерируем кандидатов для тестирования
            var candidateUrls = GenerateCandidateUrls(baseUrl);
            AnsiConsole.MarkupLine($"[yellow]Generated {candidateUrls.Count} candidate URLs for testing[/]");

            // Объединяем найденные и сгенерированные URL
            var urlsToScan = crawledUrls
                .Concat(candidateUrls)
                .Distinct()
                .Take(maxPages * 3) // Ограничиваем общее количество
                .ToList();

            AnsiConsole.MarkupLine($"[yellow]Total URLs to test: {urlsToScan.Count}[/]");

            var semaphore = new SemaphoreSlim(_maxConcurrency);
            var tasks = new List<Task<List<ScanResult>>>();

            foreach (string url in urlsToScan)
            {
                await semaphore.WaitAsync();
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        return await TestUrlForAdvancedIdorAsync(url);
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
                        if (!_results.Any(r => r.Url == scanResult.Url && r.ModifiedUrl == scanResult.ModifiedUrl && r.Parameter == scanResult.Parameter))
                        {
                            _results.Add(scanResult);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error during scan: {ex.Message}[/]");
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
            AnsiConsole.MarkupLine($"[green]JSON report saved to: [bold]{outputPath}[/][/]");
        }

        public void GenerateCsvReport(string outputPath)
        {
            var csvLines = new List<string>
            {
                "RiskLevel,TestType,Url,ModifiedUrl,Parameter,OriginalValue,TestValue,Confidence,Details,OriginalStatus,ModifiedStatus,HttpMethod,ContentType,VulnerableDataSample"
            };

            foreach (var result in _results)
            {
                csvLines.Add($"{result.RiskLevel},{result.TestType},{result.Url},{result.ModifiedUrl},{result.Parameter}," +
                            $"{result.OriginalValue},{result.TestValue},{result.Confidence:F2},{result.Details.Replace(",", ";")}," +
                            $"{result.OriginalStatusCode},{result.ModifiedStatusCode},{result.HttpMethod ?? "GET"},{result.ContentType ?? "N/A"}," +
                            $"\"{result.VulnerableDataSample.Replace("\"", "\"\"")}\"");
            }

            File.WriteAllLines(outputPath, csvLines);
            AnsiConsole.MarkupLine($"[green]CSV report saved to: [bold]{outputPath}[/][/]");
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
            var criticalRiskFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 10, BaseColor.RED);
            var highRiskFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 10, new BaseColor(200, 0, 0));
            var mediumRiskFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 10, new BaseColor(255, 165, 0));
            var lowRiskFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 10, new BaseColor(0, 150, 0));

            pdfDoc.Add(new iTextSharp.text.Paragraph("ADVANCED IDOR SCAN REPORT", titleFont) { Alignment = Element.ALIGN_CENTER });
            pdfDoc.Add(new iTextSharp.text.Paragraph($"Target: {_httpClient.BaseAddress}", subtitleFont) { Alignment = Element.ALIGN_CENTER });
            pdfDoc.Add(new iTextSharp.text.Paragraph($"Scan Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}", subtitleFont) { Alignment = Element.ALIGN_CENTER });
            pdfDoc.Add(new iTextSharp.text.Paragraph($"Total Vulnerabilities Found: {_results.Count}", subtitleFont) { Alignment = Element.ALIGN_CENTER });
            pdfDoc.Add(new iTextSharp.text.Paragraph(" "));

            pdfDoc.Add(new iTextSharp.text.Paragraph("Advanced techniques used:", subtitleFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- Parameter pollution testing", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- JSON globbing (arrays, booleans, wildcards)", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- HTTP method variations (POST, PUT)", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- Content-Type header manipulation", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- API version enumeration", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- Static keyword replacement (current, me)", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("- UUID and unpredictable ID enumeration", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph(" "));

            // Статистика по уровням риска
            var criticalRisk = _results.Count(r => r.RiskLevel == "CRITICAL");
            var highRisk = _results.Count(r => r.RiskLevel == "HIGH");
            var mediumRisk = _results.Count(r => r.RiskLevel == "MEDIUM");
            var lowRisk = _results.Count(r => r.RiskLevel == "LOW");

            pdfDoc.Add(new iTextSharp.text.Paragraph($"CRITICAL RISK: {criticalRisk} vulnerabilities", criticalRiskFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph($"HIGH RISK: {highRisk} vulnerabilities", highRiskFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph($"MEDIUM RISK: {mediumRisk} vulnerabilities", mediumRiskFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph($"LOW RISK: {lowRisk} vulnerabilities", lowRiskFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph(" "));

            // Детальные результаты
            foreach (var result in _results)
            {
                var riskFont = result.RiskLevel == "CRITICAL" ? criticalRiskFont :
                              result.RiskLevel == "HIGH" ? highRiskFont :
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

                if (!string.IsNullOrEmpty(result.VulnerableDataSample))
                {
                    pdfDoc.Add(new iTextSharp.text.Paragraph($"Vulnerable Data Sample: {result.VulnerableDataSample.Substring(0, Math.Min(150, result.VulnerableDataSample.Length))}...", normalFont));
                }

                pdfDoc.Add(new iTextSharp.text.Paragraph(new string('-', 50)));
                pdfDoc.Add(new iTextSharp.text.Paragraph(" "));
            }

            // Рекомендации
            pdfDoc.Add(new iTextSharp.text.Paragraph("REMEDIATION RECOMMENDATIONS", subtitleFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph(" "));
            pdfDoc.Add(new iTextSharp.text.Paragraph("1. Implement proper access control checks for all sensitive resources", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("2. Use indirect reference maps instead of direct object references", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("3. Always validate that the requesting user has permissions to access the requested object", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("4. Implement logging and monitoring for suspicious access patterns", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("5. Use UUIDs instead of sequential IDs for sensitive resources", normalFont));
            pdfDoc.Add(new iTextSharp.text.Paragraph("6. Implement proper authorization checks on both GET and POST/PUT requests", normalFont));

            pdfDoc.Close();
            AnsiConsole.MarkupLine($"[green]PDF report saved to: [bold]{outputPath}[/][/]");
        }
    }

    // Оставшиеся классы (ScanOptions, Program, вспомогательные классы) остались без изменений
    // ...
}