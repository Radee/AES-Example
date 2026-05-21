using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Forms;
using NbpRateTracker.Models;
using NbpRateTracker.Services;

namespace NbpRateTracker;

public partial class Form1 : Form
{
    private readonly NbpService _nbpService;

    public Form1()
    {
        InitializeComponent();
        _nbpService = new NbpService();
    }

    private async void Form1_Load(object sender, EventArgs e)
    {
        await LoadRates();
    }

    private async void btnRefresh_Click(object sender, EventArgs e)
    {
        await LoadRates();
    }

    private async Task LoadRates()
    {
        try
        {
            btnRefresh.Enabled = false;
            lblStatus.Text = "Fetching data...";

            var rates = await _nbpService.GetCurrentRatesAsync();

            dgvRates.DataSource = rates;

            // Customize columns if needed
            var colCurrency = dgvRates.Columns["Currency"];
            if (colCurrency != null) colCurrency.HeaderText = "Currency Name";

            var colCode = dgvRates.Columns["Code"];
            if (colCode != null) colCode.HeaderText = "Currency Code";

            var colMid = dgvRates.Columns["Mid"];
            if (colMid != null) colMid.HeaderText = "Exchange Rate";

            lblStatus.Text = $"Last updated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error loading rates: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            lblStatus.Text = "Failed to update.";
        }
        finally
        {
            btnRefresh.Enabled = true;
        }
    }
}
