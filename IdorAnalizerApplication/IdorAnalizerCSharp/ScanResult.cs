namespace IdorAnalizerCSharp
{
    public class ScanResult
    {
        public string Url { get; set; }
        public string ModifiedUrl { get; set; }
        public string Parameter { get; set; }
        public string OriginalValue { get; set; }
        public string TestValue { get; set; }
        public string TestType { get; set; }
        public string HttpMethod { get; set; }
        public string ContentType { get; set; }
        public bool IsVulnerable { get; set; }
        public double Confidence { get; set; }
        public string RiskLevel { get; set; }
        public string Details { get; set; }
        public int OriginalStatusCode { get; set; }
        public int ModifiedStatusCode { get; set; }
        public int OriginalContentLength { get; set; }
        public int ModifiedContentLength { get; set; }
        public DateTime ScanTime { get; set; } = DateTime.Now;
        public string VulnerableDataSample { get; set; } = "";
    }
}
