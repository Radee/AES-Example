using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace NbpRateTracker.Models
{
    public class NbpTableResponse
    {
        [JsonPropertyName("table")]
        public string Table { get; set; } = string.Empty;

        [JsonPropertyName("no")]
        public string Number { get; set; } = string.Empty;

        [JsonPropertyName("effectiveDate")]
        public string EffectiveDate { get; set; } = string.Empty;

        [JsonPropertyName("rates")]
        public List<NbpRate> Rates { get; set; } = new List<NbpRate>();
    }

    public class NbpRate
    {
        [JsonPropertyName("currency")]
        public string Currency { get; set; } = string.Empty;

        [JsonPropertyName("code")]
        public string Code { get; set; } = string.Empty;

        [JsonPropertyName("mid")]
        public decimal Mid { get; set; }
    }
}
