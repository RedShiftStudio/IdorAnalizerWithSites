using System.Net;
using System.Net.Http.Headers;
using CommandLine;
using Spectre.Console;

namespace IdorAnalizerCSharp
{
    public class Program
    {
        static async Task Main(string[] args)
        {
            try
            {
                // ваш текущий код парсинга и вызова RunScanAsync
                var parser = new Parser(settings => settings.HelpWriter = null);
                var result = parser.ParseArguments<ScanOptions>(args);
                await result.MapResult(
                    async options => await RunScanAsync(options),
                    errors => Task.CompletedTask
                );
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteException(ex);
                Console.WriteLine($"КРИТИЧЕСКАЯ ОШИБКА: {ex}");
            }
        }

        static async Task RunScanAsync(ScanOptions options)
        {
            // Вывод баннера
            AnsiConsole.WriteLine(new string('=', 60));
            AnsiConsole.WriteLine("[cyan]ADVANCED IDOR Scanner v2.0[/]");
            AnsiConsole.WriteLine("[cyan]With integrated techniques from Habr article: https://habr.com/ru/articles/848116/[/]");
            AnsiConsole.WriteLine("[cyan]Supporting: parameter pollution, JSON globbing, HTTP method variations, content-type testing, API version testing[/]");
            AnsiConsole.WriteLine(new string('=', 60));
            AnsiConsole.WriteLine($"[white]Target URL: [bold]{options.Url}[/][/]");
            AnsiConsole.WriteLine($"[white]Threads: {options.Threads}[/]");
            AnsiConsole.WriteLine($"[white]Sensitivity: {options.Sensitivity:F2}[/]");
            AnsiConsole.WriteLine($"[white]Max Pages: {options.MaxPages}[/]");
            AnsiConsole.WriteLine($"[yellow]Advanced mode: {(options.Advanced ? "ENABLED" : "DISABLED")}[/]");
            AnsiConsole.WriteLine(new string('=', 60));
            AnsiConsole.WriteLine();

            // Настройка HTTP клиента
            var httpClientHandler = new HttpClientHandler
            {
                AllowAutoRedirect = true,
                MaxConnectionsPerServer = options.Threads,
                UseCookies = true
            };

            // Отключение проверки SSL для тестирования
            httpClientHandler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;

            if (httpClientHandler.SupportsAutomaticDecompression)
            {
                httpClientHandler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            }

            var httpClient = new HttpClient(httpClientHandler)
            {
                Timeout = TimeSpan.FromSeconds(options.Timeout)
            };

            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Advanced-IDOR-Scanner/2.0 (Security Research)");

            // Установка заголовков
            if (!string.IsNullOrEmpty(options.Headers))
            {
                var headers = options.Headers.Split(',')
                    .Select(h => h.Split(':', 2))
                    .Where(h => h.Length == 2)
                    .ToDictionary(h => h[0].Trim(), h => h[1].Trim());

                foreach (var header in headers)
                {
                    if (header.Key.Equals("user-agent", StringComparison.OrdinalIgnoreCase))
                    {
                        httpClient.DefaultRequestHeaders.UserAgent.Clear();
                        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(header.Value);
                    }
                    else if (header.Key.Equals("accept", StringComparison.OrdinalIgnoreCase))
                    {
                        httpClient.DefaultRequestHeaders.Accept.Clear();
                        httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(header.Value));
                    }
                    else if (header.Key.Equals("accept-language", StringComparison.OrdinalIgnoreCase))
                    {
                        httpClient.DefaultRequestHeaders.AcceptLanguage.Clear();
                        foreach (var lang in header.Value.Split(','))
                        {
                            httpClient.DefaultRequestHeaders.AcceptLanguage.Add(new StringWithQualityHeaderValue(lang.Trim()));
                        }
                    }
                    else if (header.Key.StartsWith("x-") || header.Key.StartsWith("custom-"))
                    {
                        httpClient.DefaultRequestHeaders.Add(header.Key, header.Value);
                    }
                }
            }

            // Установка cookies
            if (!string.IsNullOrEmpty(options.Cookies))
            {
                var cookies = new CookieContainer();
                var uri = new Uri(options.Url);

                var cookiePairs = options.Cookies.Split(';')
                    .Select(c => c.Trim().Split('=', 2))
                    .Where(c => c.Length == 2)
                    .Select(c => new { Name = c[0].Trim(), Value = c[1].Trim() });

                foreach (var cookie in cookiePairs)
                {
                    try
                    {
                        cookies.Add(uri, new Cookie(cookie.Name, cookie.Value));
                    }
                    catch (Exception ex)
                    {
                        AnsiConsole.WriteLine($"[yellow]Warning: Could not add cookie {cookie.Name}: {ex.Message}[/]");
                    }
                }

                if (httpClientHandler is HttpClientHandler handler)
                {
                    handler.CookieContainer = cookies;
                }
            }

            // Создание и запуск сканера
            var scanner = new AdvancedIdorScanner(httpClient, options.Threads, options.Sensitivity, options.Timeout);
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                AnsiConsole.WriteLine("[cyan][*] Starting advanced scan...[/]");
                var results = await scanner.ScanAsync(options.Url, options.MaxPages);
                stopwatch.Stop();

                AnsiConsole.WriteLine();
                AnsiConsole.WriteLine(new string('=', 60));
                AnsiConsole.WriteLine("[cyan]SCAN COMPLETED[/]");
                AnsiConsole.WriteLine(new string('=', 60));
                AnsiConsole.WriteLine($"[white]Scan duration: {stopwatch.Elapsed.TotalSeconds:F2} seconds[/]");
                AnsiConsole.WriteLine($"[white]Vulnerabilities found: {results.Count}[/]");
                AnsiConsole.WriteLine(new string('=', 60));
                AnsiConsole.WriteLine();

                // Отображение результатов
                if (results.Count > 0)
                {
                    var table = new Table();
                    table.AddColumn("Risk");
                    table.AddColumn("Test Type");
                    table.AddColumn("URL");
                    table.AddColumn("Parameter");
                    table.AddColumn("Confidence");

                    foreach (var result in results)
                    {
                        var riskColor = result.RiskLevel == "HIGH" ? Color.Red :
                                       result.RiskLevel == "MEDIUM" ? Color.Yellow : Color.Green;

                        table.AddRow(
                            new Markup($"[{riskColor}]{result.RiskLevel}[/]"),
                            new Markup($"[{riskColor}]{result.TestType}[/]"),
                            new Markup($"[{riskColor}]{result.Url.Substring(0, Math.Min(result.Url.Length, 40))}[/]"),
                            new Markup($"[{riskColor}]{result.Parameter}[/]"),
                            new Markup($"[{riskColor}]{result.Confidence:F2}[/]")
                        );
                    }

                    AnsiConsole.Write(table);
                }
                else
                {
                    AnsiConsole.WriteLine("[green][+] No IDOR vulnerabilities found.[/]");
                }

                // Генерация отчета
                if (!string.IsNullOrEmpty(options.Output))
                {
                    string outputPath = options.Output;
                    string format = options.Format.ToLower();

                    switch (format)
                    {
                        case "json":
                            scanner.GenerateJsonReport(outputPath);
                            break;
                        case "csv":
                            scanner.GenerateCsvReport(outputPath);
                            break;
                        case "pdf":
                            scanner.GeneratePdfReport(outputPath);
                            break;
                        default:
                            AnsiConsole.WriteLine($"[yellow]Unsupported format: {format}. Using JSON.[/]");
                            scanner.GenerateJsonReport(outputPath);
                            break;
                    }
                }

                // Рекомендации по исправлению
                if (results.Count > 0)
                {
                    AnsiConsole.WriteLine();
                    AnsiConsole.WriteLine(new string('=', 60));
                    AnsiConsole.WriteLine("[cyan]REMEDIATION RECOMMENDATIONS[/]");
                    AnsiConsole.WriteLine(new string('=', 60));
                    AnsiConsole.WriteLine("[yellow]1. Implement proper access control checks for all sensitive resources[/]");
                    AnsiConsole.WriteLine("[yellow]2. Use indirect reference maps instead of direct object references[/]");
                    AnsiConsole.WriteLine("[yellow]3. Implement role-based access control (RBAC) for all user operations[/]");
                    AnsiConsole.WriteLine("[yellow]4. Validate all user input and implement proper authorization checks[/]");
                    AnsiConsole.WriteLine("[yellow]5. Use UUIDs instead of sequential IDs for sensitive resources[/]");
                    AnsiConsole.WriteLine("[yellow]6. Implement logging and monitoring for unauthorized access attempts[/]");
                    AnsiConsole.WriteLine("[yellow]7. Test all HTTP methods and content types for access control bypass[/]");
                    AnsiConsole.WriteLine("[yellow]8. Regularly audit API versions and disable old, insecure versions[/]");
                    AnsiConsole.WriteLine("[yellow]9. Implement proper validation for JSON data structures[/]");
                    AnsiConsole.WriteLine("[yellow]10. Use parameter binding and strict type checking to prevent parameter pollution[/]");
                    AnsiConsole.WriteLine(new string('=', 60));
                }
            }
            catch (OperationCanceledException)
            {
                AnsiConsole.WriteLine("[red][-] Scan interrupted by user[/]");
            }
            catch (Exception ex)
            {
                AnsiConsole.WriteLine($"[red][-] Critical error during scan: {ex.Message}[/]");
                if (options.Verbose)
                {
                    AnsiConsole.WriteException(ex);
                }
            }
        }

        static void HandleParseErrors(IEnumerable<Error> errors)
        {
            AnsiConsole.WriteLine("[red]Error parsing command line arguments[/]");
            foreach (var error in errors)
            {
                AnsiConsole.WriteLine($"[red]- {error}[/]");
            }
        }
    }
}
