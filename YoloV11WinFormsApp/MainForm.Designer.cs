namespace YoloV11WinFormsApp
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;
        private System.Windows.Forms.PictureBox pictureBox;
        private System.Windows.Forms.Button btnLoadImage;
        private System.Windows.Forms.Button btnToggleWebcam;
        private System.Windows.Forms.RadioButton rbDetection;
        private System.Windows.Forms.RadioButton rbClassification;
        private System.Windows.Forms.GroupBox groupBoxMode;
        private System.Windows.Forms.Label lblStatus;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.pictureBox = new System.Windows.Forms.PictureBox();
            this.btnLoadImage = new System.Windows.Forms.Button();
            this.btnToggleWebcam = new System.Windows.Forms.Button();
            this.rbDetection = new System.Windows.Forms.RadioButton();
            this.rbClassification = new System.Windows.Forms.RadioButton();
            this.groupBoxMode = new System.Windows.Forms.GroupBox();
            this.lblStatus = new System.Windows.Forms.Label();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox)).BeginInit();
            this.groupBoxMode.SuspendLayout();
            this.SuspendLayout();
            //
            // pictureBox
            //
            this.pictureBox.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
            | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.pictureBox.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.pictureBox.Location = new System.Drawing.Point(12, 12);
            this.pictureBox.Name = "pictureBox";
            this.pictureBox.Size = new System.Drawing.Size(776, 426);
            this.pictureBox.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.pictureBox.TabIndex = 0;
            this.pictureBox.TabStop = false;
            //
            // btnLoadImage
            //
            this.btnLoadImage.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.btnLoadImage.Location = new System.Drawing.Point(12, 444);
            this.btnLoadImage.Name = "btnLoadImage";
            this.btnLoadImage.Size = new System.Drawing.Size(120, 40);
            this.btnLoadImage.TabIndex = 1;
            this.btnLoadImage.Text = "Load Image";
            this.btnLoadImage.UseVisualStyleBackColor = true;
            this.btnLoadImage.Click += new System.EventHandler(this.btnLoadImage_Click);
            //
            // btnToggleWebcam
            //
            this.btnToggleWebcam.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.btnToggleWebcam.Location = new System.Drawing.Point(138, 444);
            this.btnToggleWebcam.Name = "btnToggleWebcam";
            this.btnToggleWebcam.Size = new System.Drawing.Size(120, 40);
            this.btnToggleWebcam.TabIndex = 2;
            this.btnToggleWebcam.Text = "Start Webcam";
            this.btnToggleWebcam.UseVisualStyleBackColor = true;
            this.btnToggleWebcam.Click += new System.EventHandler(this.btnToggleWebcam_Click);
            //
            // rbDetection
            //
            this.rbDetection.AutoSize = true;
            this.rbDetection.Checked = true;
            this.rbDetection.Location = new System.Drawing.Point(6, 19);
            this.rbDetection.Name = "rbDetection";
            this.rbDetection.Size = new System.Drawing.Size(103, 17);
            this.rbDetection.TabIndex = 3;
            this.rbDetection.TabStop = true;
            this.rbDetection.Text = "Object Detection";
            this.rbDetection.UseVisualStyleBackColor = true;
            //
            // rbClassification
            //
            this.rbClassification.AutoSize = true;
            this.rbClassification.Location = new System.Drawing.Point(115, 19);
            this.rbClassification.Name = "rbClassification";
            this.rbClassification.Size = new System.Drawing.Size(86, 17);
            this.rbClassification.TabIndex = 4;
            this.rbClassification.Text = "Classification";
            this.rbClassification.UseVisualStyleBackColor = true;
            //
            // groupBoxMode
            //
            this.groupBoxMode.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBoxMode.Controls.Add(this.rbDetection);
            this.groupBoxMode.Controls.Add(this.rbClassification);
            this.groupBoxMode.Location = new System.Drawing.Point(588, 444);
            this.groupBoxMode.Name = "groupBoxMode";
            this.groupBoxMode.Size = new System.Drawing.Size(200, 45);
            this.groupBoxMode.TabIndex = 5;
            this.groupBoxMode.TabStop = false;
            this.groupBoxMode.Text = "Mode";
            //
            // lblStatus
            //
            this.lblStatus.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.lblStatus.AutoSize = true;
            this.lblStatus.ForeColor = System.Drawing.Color.Red;
            this.lblStatus.Location = new System.Drawing.Point(264, 458);
            this.lblStatus.Name = "lblStatus";
            this.lblStatus.Size = new System.Drawing.Size(0, 13);
            this.lblStatus.TabIndex = 6;
            //
            // MainForm
            //
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 496);
            this.Controls.Add(this.lblStatus);
            this.Controls.Add(this.groupBoxMode);
            this.Controls.Add(this.btnToggleWebcam);
            this.Controls.Add(this.btnLoadImage);
            this.Controls.Add(this.pictureBox);
            this.Name = "MainForm";
            this.Text = "YOLOv11 WinForms App";
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox)).EndInit();
            this.groupBoxMode.ResumeLayout(false);
            this.groupBoxMode.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }
    }
}
