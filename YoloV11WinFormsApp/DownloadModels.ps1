# Download YOLOv11 ONNX Models

Write-Host "Downloading YOLOv11 Nano Detection Model (Opset 17)..."
# Note: Using v8.3.0 assets. If these contain Opset 22, we may need to use a different source or user-export.
# However, Opset 17 is generally recommended for widest compatibility.
Invoke-WebRequest -Uri "https://github.com/ultralytics/assets/releases/download/v8.3.0/yolo11n.onnx" -OutFile "yolo11n.onnx"

Write-Host "Downloading YOLOv11 Nano Classification Model (Opset 17)..."
Invoke-WebRequest -Uri "https://github.com/ultralytics/assets/releases/download/v8.3.0/yolo11n-cls.onnx" -OutFile "yolo11n-cls.onnx"

Write-Host "Done! Please ensure these files are in the same folder as the executable or in the project root."
Write-Host ""
Write-Host "CRITICAL NOTE: If you still get Opset errors, you can manually export the models using Python:"
Write-Host "pip install ultralytics"
Write-Host "yolo export model=yolo11n.pt format=onnx opset=17"
Write-Host "yolo export model=yolo11n-cls.pt format=onnx opset=17"
