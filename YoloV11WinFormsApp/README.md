# YOLOv11 WinForms Application

This is a C# WinForms application targeting .NET Framework 4.8.1 that uses YOLOv11 (via ONNX Runtime) for real-time object detection and image classification.

## Features
- **Object Detection**: Identifies objects in images/webcam using the YOLOv11n model.
- **Image Classification**: Classifies the main subject using the YOLOv11n-cls model.
- **Webcam Support**: Real-time inference from your default camera.
- **Image Loading**: Process static images from your disk.

## Prerequisites
- **Visual Studio 2022** with ".NET desktop development" workload.
- **.NET Framework 4.8.1 SDK**.

## Setup Instructions

1. **Download the Models**:
   - Open PowerShell.
   - Navigate to the project directory.
   - Run: `./DownloadModels.ps1`
   - Alternatively, manually download `yolo11n.onnx` and `yolo11n-cls.onnx` from [Ultralytics Assets](https://github.com/ultralytics/assets/releases) and place them in the project root or the `bin\Debug` folder.

2. **Open the Project**:
   - Open `YoloV11WinFormsApp.csproj` in Visual Studio 2022.

3. **Restore NuGet Packages**:
   - Visual Studio should automatically restore packages. If not, right-click the Solution and select **Restore NuGet Packages**.
   - Essential packages: `Microsoft.ML.OnnxRuntime`, `OpenCvSharp4`, `OpenCvSharp4.Extensions`, `OpenCvSharp4.runtime.win`.

4. **Build and Run**:
   - Set the configuration to `Debug` or `Release`.
   - **IMPORTANT**: Ensure the Solution Platform is set to **x64**. The ONNX Runtime and OpenCV native libraries require the application to run in 64-bit mode.
   - Press **F5** to run the application.

## Troubleshooting

### Architecture Error (`EntryPointNotFoundException: OrtGetApiBase`)
- This usually means there is an architecture mismatch (e.g., trying to run as x86 or AnyCPU).
- Go to **Project Properties -> Build** and ensure **Platform Target** is set to **x64**.
- Clean and Rebuild the solution.

### Opset Error (`ONNX Runtime only guarantees support for models stamped with official released onnx opset versions`)
If you see an error about **Opset 22**, it means the pre-trained models you downloaded are too new for the current ONNX Runtime.
To fix this, you should export the models manually using a compatible Opset (like 17):
1. Install Ultralytics: `pip install ultralytics`
2. Export Detection: `yolo export model=yolo11n.pt format=onnx opset=17`
3. Export Classification: `yolo export model=yolo11n-cls.pt format=onnx opset=17`
4. Replace the `.onnx` files in your project with these new ones.

## Note on Architecture
The app is designed to work on Windows (due to `OpenCvSharp4.runtime.win` and WinForms). The project is explicitly configured for `win-x64`.
