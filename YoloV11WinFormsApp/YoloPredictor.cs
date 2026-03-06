using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using OpenCvSharp;
using OpenCvSharp.Extensions;

namespace YoloV11WinFormsApp
{
    public class PredictionResult
    {
        public RectangleF Rect { get; set; }
        public string Label { get; set; }
        public float Confidence { get; set; }
    }

    public class YoloPredictor : IDisposable
    {
        private InferenceSession _session;
        private readonly string[] _labels;
        private bool _isClassification;

        public YoloPredictor(string modelPath, string[] labels, bool isClassification = false)
        {
            _session = new InferenceSession(modelPath);
            _labels = labels;
            _isClassification = isClassification;
        }

        public List<PredictionResult> Predict(Mat image)
        {
            if (_isClassification)
                return PredictClassification(image);
            else
                return PredictDetection(image);
        }

        private List<PredictionResult> PredictDetection(Mat image)
        {
            int modelInputWidth = 640;
            int modelInputHeight = 640;

            using var resized = new Mat();
            Cv2.Resize(image, resized, new OpenCvSharp.Size(modelInputWidth, modelInputHeight));

            var input = MatToFloatArray(resized);
            var inputTensor = new DenseTensor<float>(input, new[] { 1, 3, modelInputHeight, modelInputWidth });

            var inputs = new List<NamedOnnxValue>
            {
                NamedOnnxValue.CreateFromTensor("images", inputTensor)
            };

            using var results = _session.Run(inputs);
            var output = results.First().AsEnumerable<float>().ToArray();

            // YOLOv11 output shape is typically [1, 84, 8400] (for 80 classes)
            // It might be transposed depending on how it was exported.
            // Standard Ultralytics ONNX export: [1, 4+classes, 8400]

            return ParseDetectionOutput(output, image.Width, image.Height);
        }

        private List<PredictionResult> PredictClassification(Mat image)
        {
            int modelInputWidth = 224; // Standard for classification
            int modelInputHeight = 224;

            using var resized = new Mat();
            Cv2.Resize(image, resized, new OpenCvSharp.Size(modelInputWidth, modelInputHeight));

            var input = MatToFloatArray(resized);
            var inputTensor = new DenseTensor<float>(input, new[] { 1, 3, modelInputHeight, modelInputWidth });

            var inputs = new List<NamedOnnxValue>
            {
                NamedOnnxValue.CreateFromTensor("images", inputTensor)
            };

            using var results = _session.Run(inputs);
            var output = results.First().AsEnumerable<float>().ToArray();

            // Find the index with the highest probability
            int maxIndex = 0;
            float maxScore = 0;
            for (int i = 0; i < output.Length; i++)
            {
                if (output[i] > maxScore)
                {
                    maxScore = output[i];
                    maxIndex = i;
                }
            }

            return new List<PredictionResult>
            {
                new PredictionResult
                {
                    Label = _labels.Length > maxIndex ? _labels[maxIndex] : $"Class {maxIndex}",
                    Confidence = maxScore,
                    Rect = RectangleF.Empty
                }
            };
        }

        private List<PredictionResult> ParseDetectionOutput(float[] output, int originalWidth, int originalHeight)
        {
            var results = new List<PredictionResult>();
            int rows = 8400; // number of boxes
            int dimensions = 84; // 4 boxes + 80 classes

            // Note: Output is often flattened in a way that needs careful indexing
            // Usually it is [1, 84, 8400] which means all x-coords, then all y-coords, etc.

            for (int i = 0; i < rows; i++)
            {
                float maxScore = 0;
                int classId = -1;

                for (int j = 4; j < dimensions; j++)
                {
                    float score = output[j * rows + i];
                    if (score > maxScore)
                    {
                        maxScore = score;
                        classId = j - 4;
                    }
                }

                if (maxScore > 0.4f)
                {
                    float x = output[0 * rows + i];
                    float y = output[1 * rows + i];
                    float w = output[2 * rows + i];
                    float h = output[3 * rows + i];

                    float xMin = (x - w / 2) * originalWidth / 640f;
                    float yMin = (y - h / 2) * originalHeight / 640f;
                    float width = w * originalWidth / 640f;
                    float height = h * originalHeight / 640f;

                    results.Add(new PredictionResult
                    {
                        Label = _labels.Length > classId ? _labels[classId] : $"Class {classId}",
                        Confidence = maxScore,
                        Rect = new RectangleF(xMin, yMin, width, height)
                    });
                }
            }

            return ApplyNMS(results);
        }

        private List<PredictionResult> ApplyNMS(List<PredictionResult> results)
        {
            // Simple NMS implementation
            var sorted = results.OrderByDescending(r => r.Confidence).ToList();
            var final = new List<PredictionResult>();

            while (sorted.Count > 0)
            {
                var current = sorted[0];
                final.Add(current);
                sorted.RemoveAt(0);

                for (int i = sorted.Count - 1; i >= 0; i--)
                {
                    if (CalculateIoU(current.Rect, sorted[i].Rect) > 0.45f)
                    {
                        sorted.RemoveAt(i);
                    }
                }
            }

            return final;
        }

        private float CalculateIoU(RectangleF rect1, RectangleF rect2)
        {
            float intersectionArea = RectangleF.Intersect(rect1, rect2).Width * RectangleF.Intersect(rect1, rect2).Height;
            float unionArea = (rect1.Width * rect1.Height) + (rect2.Width * rect2.Height) - intersectionArea;
            return intersectionArea / unionArea;
        }

        private float[] MatToFloatArray(Mat image)
        {
            int width = image.Width;
            int height = image.Height;
            float[] result = new float[3 * width * height];

            // YOLO expects RGB and normalized [0, 1]
            // OpenCV uses BGR
            for (int y = 0; y < height; y++)
            {
                for (int x = 0; x < width; x++)
                {
                    var pixel = image.At<Vec3b>(y, x);
                    result[0 * width * height + y * width + x] = pixel.Item2 / 255.0f; // R
                    result[1 * width * height + y * width + x] = pixel.Item1 / 255.0f; // G
                    result[2 * width * height + y * width + x] = pixel.Item0 / 255.0f; // B
                }
            }
            return result;
        }

        public void Dispose()
        {
            _session?.Dispose();
        }
    }
}
