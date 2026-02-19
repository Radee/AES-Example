# WinForms Plugin System Sample (.NET Framework 4.8)

This sample demonstrates a robust plugin architecture for a WinForms application using C# and the **Managed Extensibility Framework (MEF)**.

## Project Structure

- **PluginSystem.Interfaces**: A shared class library containing the `IPlugin` interface. Both the Host and the Plugins reference this.
- **PluginSystem.MainApp**: The main WinForms application (Host). It scans the `Plugins` folder for DLLs and dynamically adds buttons to its UI for each discovered plugin.
- **PluginSystem.SamplePlugin**: An example plugin. It implements `IPlugin` and exports itself using MEF. It contains its own standalone Form.

## How it works

1.  **Discovery**: The `MainApp` uses `DirectoryCatalog` to scan a folder named `Plugins` in its execution directory.
2.  **Composition**: MEF matches the `[ImportMany(typeof(IPlugin))]` in `MainForm` with the `[Export(typeof(IPlugin))]` in the plugin DLLs.
3.  **UI Integration**: For every plugin found, a `Button` is created and added to a `FlowLayoutPanel`.
4.  **Execution**: When a button is clicked, the plugin's `Execute()` method is called, which in this sample opens a new standalone Form.

## How to run in Visual Studio 2022

1.  Open `PluginSystem.sln`.
2.  Ensure you have the **.NET Framework 4.8 targeting pack** installed in Visual Studio.
3.  Build the entire solution (**Ctrl+Shift+B**).
    - A post-build event in the `PluginSystem.SamplePlugin` project automatically copies its DLL to the `PluginSystem.MainApp\bin\Debug\net48\Plugins` folder.
4.  Set `PluginSystem.MainApp` as the Startup Project.
5.  Press **F5** to run.

## Adding New Plugins

To add a new plugin:
1.  Create a new Class Library project targeting `.NET Framework 4.8`.
2.  Add a reference to `PluginSystem.Interfaces`.
3.  Add a reference to `System.ComponentModel.Composition`.
4.  Implement `IPlugin` in a class and decorate it with `[Export(typeof(IPlugin))]`.
5.  Place the compiled DLL in the `Plugins` folder of the main application.
