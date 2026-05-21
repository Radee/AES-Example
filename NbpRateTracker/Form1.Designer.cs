namespace NbpRateTracker;

partial class Form1
{
    /// <summary>
    ///  Required designer variable.
    /// </summary>
    private System.ComponentModel.IContainer components = null;

    /// <summary>
    ///  Clean up any resources being used.
    /// </summary>
    /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
    protected override void Dispose(bool disposing)
    {
        if (disposing && (components != null))
        {
            components.Dispose();
        }
        base.Dispose(disposing);
    }

    #region Windows Form Designer generated code

    /// <summary>
    ///  Required method for Designer support - do not modify
    ///  the contents of this method with the code editor.
    /// </summary>
    private void InitializeComponent()
    {
        dgvRates = new DataGridView();
        btnRefresh = new Button();
        lblStatus = new Label();
        ((System.ComponentModel.ISupportInitialize)dgvRates).BeginInit();
        SuspendLayout();
        //
        // dgvRates
        //
        dgvRates.AllowUserToAddRows = false;
        dgvRates.AllowUserToDeleteRows = false;
        dgvRates.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        dgvRates.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        dgvRates.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
        dgvRates.Location = new Point(12, 41);
        dgvRates.Name = "dgvRates";
        dgvRates.ReadOnly = true;
        dgvRates.RowTemplate.Height = 25;
        dgvRates.Size = new Size(776, 381);
        dgvRates.TabIndex = 0;
        //
        // btnRefresh
        //
        btnRefresh.Location = new Point(12, 12);
        btnRefresh.Name = "btnRefresh";
        btnRefresh.Size = new Size(75, 23);
        btnRefresh.TabIndex = 1;
        btnRefresh.Text = "Refresh";
        btnRefresh.UseVisualStyleBackColor = true;
        btnRefresh.Click += btnRefresh_Click;
        //
        // lblStatus
        //
        lblStatus.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        lblStatus.AutoSize = true;
        lblStatus.Location = new Point(12, 426);
        lblStatus.Name = "lblStatus";
        lblStatus.Size = new Size(39, 15);
        lblStatus.TabIndex = 2;
        lblStatus.Text = "Ready";
        //
        // Form1
        //
        AutoScaleDimensions = new SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new Size(800, 450);
        Controls.Add(lblStatus);
        Controls.Add(btnRefresh);
        Controls.Add(dgvRates);
        Name = "Form1";
        Text = "NBP Exchange Rates (Table A)";
        Load += Form1_Load;
        ((System.ComponentModel.ISupportInitialize)dgvRates).EndInit();
        ResumeLayout(false);
        PerformLayout();
    }

    #endregion

    private DataGridView dgvRates;
    private Button btnRefresh;
    private Label lblStatus;
}
