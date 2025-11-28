using CommandLine;

namespace IdorAnalizerCSharp
{
    public class ScanOptions
    {
        [Value(0, MetaName = "url", HelpText = "Target URL to scan", Required = true)]
        public string Url { get; set; }

        [Option('H', "headers", HelpText = "HTTP headers")]
        public string Headers { get; set; }

        [Option('c', "cookies", HelpText = "Session cookies")]
        public string Cookies { get; set; }

        [Option('t', "threads", Default = 5, HelpText = "Number of concurrent threads")]
        public int Threads { get; set; }

        [Option('s', "sensitivity", Default = 0.8, HelpText = "Sensitivity level")]
        public double Sensitivity { get; set; }

        [Option('T', "timeout", Default = 10, HelpText = "Request timeout in seconds")]
        public int Timeout { get; set; }

        [Option('m', "max-pages", Default = 20, HelpText = "Maximum pages to crawl")]
        public int MaxPages { get; set; }

        [Option('o', "output", HelpText = "Output report file")]
        public string Output { get; set; }

        [Option('f', "format", Default = "json", HelpText = "Report format")]
        public string Format { get; set; }

        [Option('v', "verbose", HelpText = "Enable verbose output")]
        public bool Verbose { get; set; }

        [Option('a', "advanced", HelpText = "Enable advanced scanning techniques")]
        public bool Advanced { get; set; }
    }
}
