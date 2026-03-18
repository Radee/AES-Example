using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace TetaApiDemo;

class Program
{
    private static readonly HttpClient client = new HttpClient();
    private const string TokenUrl = "https://tetaapidemo.unit4.com/ords/api/oauth/token";
    private const string ApiUrl = "https://tetaapidemo.unit4.com/ords/api/open-api-catalog/v1/personnel/";
    private const string Scope = "oAuth2ClientCredentials";

    static async Task Main(string[] args)
    {
        string? clientId = null;
        string? clientSecret = null;

        if (args.Length >= 2)
        {
            clientId = args[0];
            clientSecret = args[1];
        }
        else
        {
            Console.WriteLine("Teta API OAuth2 Demo");
            Console.Write("Enter client_id: ");
            clientId = Console.ReadLine();
            Console.Write("Enter client_secret: ");
            clientSecret = Console.ReadLine();
        }

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
        {
            Console.WriteLine("Error: client_id and client_secret are required.");
            return;
        }

        try
        {
            string token = await GetAccessTokenAsync(clientId, clientSecret);
            Console.WriteLine("Successfully obtained access token.");

            await CallSampleApiAsync(token);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }
    }

    private static async Task<string> GetAccessTokenAsync(string clientId, string clientSecret)
    {
        var requestData = new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "scope", Scope }
        };

        var requestContent = new FormUrlEncodedContent(requestData);

        // OAuth2 standard and ORDS often prefer Basic Auth for Client Credentials.
        // Format: Authorization: Basic Base64(client_id:client_secret)
        var authHeaderValue = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));

        using var request = new HttpRequestMessage(HttpMethod.Post, TokenUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", authHeaderValue);
        request.Content = requestContent;

        var response = await client.SendAsync(request);
        var responseContent = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new Exception($"Failed to obtain token. Status: {response.StatusCode}, Response: {responseContent}");
        }

        using var doc = JsonDocument.Parse(responseContent);
        if (doc.RootElement.TryGetProperty("access_token", out var tokenElement))
        {
            return tokenElement.GetString() ?? throw new Exception("Token was null in response.");
        }

        throw new Exception("access_token property not found in response.");
    }

    private static async Task CallSampleApiAsync(string token)
    {
        Console.WriteLine($"Calling API: {ApiUrl}");

        using var request = new HttpRequestMessage(HttpMethod.Get, ApiUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.SendAsync(request);
        var responseContent = await response.Content.ReadAsStringAsync();

        if (response.IsSuccessStatusCode)
        {
            Console.WriteLine("API call successful!");
            Console.WriteLine("Response summary:");
            Console.WriteLine(responseContent.Length > 500 ? responseContent.Substring(0, 500) + "..." : responseContent);
        }
        else
        {
            Console.WriteLine($"API call failed. Status: {response.StatusCode}");
            Console.WriteLine($"Response: {responseContent}");
        }
    }
}
