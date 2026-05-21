using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using NbpRateTracker.Models;

namespace NbpRateTracker.Services
{
    public class NbpService
    {
        // Reusing HttpClient is recommended practice to avoid socket exhaustion.
        private static readonly HttpClient _httpClient = new HttpClient();
        private const string ApiUrl = "https://api.nbp.pl/api/exchangerates/tables/A?format=json";

        static NbpService()
        {
            // NBP API sometimes requires a User-Agent header
            if (!_httpClient.DefaultRequestHeaders.Contains("User-Agent"))
            {
                _httpClient.DefaultRequestHeaders.Add("User-Agent", "NbpRateTracker-App");
            }
        }

        public async Task<List<NbpRate>> GetCurrentRatesAsync()
        {
            try
            {
                var response = await _httpClient.GetStringAsync(ApiUrl);
                var tables = JsonSerializer.Deserialize<List<NbpTableResponse>>(response);

                if (tables != null && tables.Count > 0)
                {
                    return tables[0].Rates;
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to fetch rates from NBP API", ex);
            }

            return new List<NbpRate>();
        }
    }
}
