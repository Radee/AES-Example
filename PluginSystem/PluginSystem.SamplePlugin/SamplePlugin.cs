using System.ComponentModel.Composition;
using PluginSystem.Interfaces;

namespace PluginSystem.SamplePlugin
{
    [Export(typeof(IPlugin))]
    public class SamplePlugin : IPlugin
    {
        public string Name => "Sample Plugin";

        public string Description => "This is a sample plugin that opens a new window.";

        public void Execute()
        {
            SamplePluginForm form = new SamplePluginForm();
            form.Show(); // Show as standalone window
        }
    }
}
