using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using OpenCvSharp;
using OpenCvSharp.Extensions;

namespace YoloV11WinFormsApp
{
    public partial class MainForm : Form
    {
        private VideoCapture _capture;
        private CancellationTokenSource _cts;
        private YoloPredictor _detector;
        private YoloPredictor _classifier;
        private bool _isWebcamRunning = false;

        // COCO labels for detection
        private readonly string[] _cocoLabels = new string[] { "person", "bicycle", "car", "motorcycle", "airplane", "bus", "train", "truck", "boat", "traffic light", "fire hydrant", "stop sign", "parking meter", "bench", "bird", "cat", "dog", "horse", "sheep", "cow", "elephant", "bear", "zebra", "giraffe", "backpack", "umbrella", "handbag", "tie", "suitcase", "frisbee", "skis", "snowboard", "sports ball", "kite", "baseball bat", "baseball glove", "skateboard", "surfboard", "tennis racket", "bottle", "wine glass", "cup", "fork", "knife", "spoon", "bowl", "banana", "apple", "sandwich", "orange", "broccoli", "carrot", "hot dog", "pizza", "donut", "cake", "chair", "couch", "potted plant", "bed", "dining table", "toilet", "tv", "laptop", "mouse", "remote", "keyboard", "cell phone", "microwave", "oven", "toaster", "sink", "refrigerator", "book", "clock", "vase", "scissors", "teddy bear", "hair drier", "toothbrush" };

        public MainForm()
        {
            InitializeComponent();
            LoadModels();
        }

        private void LoadModels()
        {
            string detectionModel = "yolo11n.onnx";
            string classificationModel = "yolo11n-cls.onnx";

            if (File.Exists(detectionModel))
                _detector = new YoloPredictor(detectionModel, _cocoLabels, false);

            if (File.Exists(classificationModel))
                _classifier = new YoloPredictor(classificationModel, new string[0], true); // Labels could be loaded from a file
        }

        private async void btnLoadImage_Click(object sender, EventArgs e)
        {
            using OpenFileDialog ofd = new OpenFileDialog();
            ofd.Filter = "Image Files|*.jpg;*.jpeg;*.png;*.bmp";
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                StopWebcam();
                Mat mat = Cv2.ImRead(ofd.FileName);
                ProcessAndDisplay(mat);
            }
        }

        private void btnToggleWebcam_Click(object sender, EventArgs e)
        {
            if (_isWebcamRunning)
            {
                StopWebcam();
            }
            else
            {
                StartWebcam();
            }
        }

        private void StartWebcam()
        {
            _capture = new VideoCapture(0);
            if (!_capture.IsOpened())
            {
                MessageBox.Show("Could not open webcam.");
                return;
            }

            _isWebcamRunning = true;
            btnToggleWebcam.Text = "Stop Webcam";
            _cts = new CancellationTokenSource();

            Task.Run(() => RunWebcam(_cts.Token));
        }

        private void StopWebcam()
        {
            _isWebcamRunning = false;
            btnToggleWebcam.Text = "Start Webcam";
            _cts?.Cancel();
            _capture?.Dispose();
        }

        private async Task RunWebcam(CancellationToken token)
        {
            using Mat frame = new Mat();
            while (!token.IsCancellationRequested)
            {
                if (_capture.Read(frame) && !frame.Empty())
                {
                    ProcessAndDisplay(frame);
                }
                await Task.Delay(30);
            }
        }

        private void ProcessAndDisplay(Mat mat)
        {
            var predictor = rbDetection.Checked ? _detector : _classifier;
            if (predictor == null)
            {
                this.Invoke(new Action(() => lblStatus.Text = "Model not loaded. Please run the download script."));
                DisplayImage(mat);
                return;
            }

            var results = predictor.Predict(mat);

            using Mat resultMat = mat.Clone();
            foreach (var res in results)
            {
                if (rbDetection.Checked)
                {
                    Cv2.Rectangle(resultMat, new OpenCvSharp.Rect((int)res.Rect.X, (int)res.Rect.Y, (int)res.Rect.Width, (int)res.Rect.Height), Scalar.Red, 2);
                    Cv2.PutText(resultMat, $"{res.Label} {res.Confidence:P0}", new OpenCvSharp.Point(res.Rect.X, res.Rect.Y - 5), HersheyFonts.HersheySimplex, 0.5, Scalar.Red, 1);
                }
                else
                {
                    Cv2.PutText(resultMat, $"Class: {res.Label} ({res.Confidence:P0})", new OpenCvSharp.Point(10, 30), HersheyFonts.HersheySimplex, 1.0, Scalar.Green, 2);
                }
            }

            DisplayImage(resultMat);
        }

        private void DisplayImage(Mat mat)
        {
            var bitmap = BitmapConverter.ToBitmap(mat);
            this.Invoke(new Action(() => {
                pictureBox.Image?.Dispose();
                pictureBox.Image = bitmap;
            }));
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            StopWebcam();
            _detector?.Dispose();
            _classifier?.Dispose();
            base.OnFormClosing(e);
        }
    }
}
