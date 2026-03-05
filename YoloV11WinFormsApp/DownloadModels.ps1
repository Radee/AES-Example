# Download YOLOv11 ONNX Models

Write-Host "Downloading YOLOv11 Nano Detection Model..."
Invoke-WebRequest -Uri "https://github.com/ultralytics/assets/releases/download/v8.3.0/yolo11n.onnx" -OutFile "yolo11n.onnx"

Write-Host "Downloading YOLOv11 Nano Classification Model..."
Invoke-WebRequest -Uri "https://github.com/ultralytics/assets/releases/download/v8.3.0/yolo11n-cls.onnx" -OutFile "yolo11n-cls.onnx"

Write-Host "Done! Please ensure these files are in the same folder as the executable or in the project root."
