using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.ComponentModel.Composition.Hosting;
using System.IO;
using System.Windows.Forms;
using PluginSystem.Interfaces;

namespace PluginSystem.MainApp
{
    public partial class MainForm : Form
    {
        [ImportMany(typeof(IPlugin))]
        public IEnumerable<IPlugin> Plugins { get; set; }

        public MainForm()
        {
            InitializeComponent();
            LoadPlugins();
            PopulatePluginButtons();
        }

        private void LoadPlugins()
        {
            try
            {
                // Create the plugins directory if it doesn't exist
                string pluginsPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Plugins");
                if (!Directory.Exists(pluginsPath))
                {
                    Directory.CreateDirectory(pluginsPath);
                }

                // An aggregate catalog that combines multiple catalogs
                var catalog = new AggregateCatalog();

                // Adds all the parts found in the Plugins folder
                catalog.Catalogs.Add(new DirectoryCatalog(pluginsPath));

                // Create the CompositionContainer with the parts in the catalog
                var container = new CompositionContainer(catalog);

                // Fill the imports of this object
                container.ComposeParts(this);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error loading plugins: " + ex.Message, "Plugin Load Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void PopulatePluginButtons()
        {
            flowLayoutPanel1.Controls.Clear();

            if (Plugins != null)
            {
                foreach (var plugin in Plugins)
                {
                    Button btn = new Button();
                    btn.Text = plugin.Name;
                    btn.Size = new System.Drawing.Size(150, 60);
                    btn.Click += (s, e) => {
                        try
                        {
                            plugin.Execute();
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show($"Error executing plugin {plugin.Name}: {ex.Message}");
                        }
                    };

                    pluginToolTip.SetToolTip(btn, plugin.Description);

                    flowLayoutPanel1.Controls.Add(btn);
                }
            }

            if (flowLayoutPanel1.Controls.Count == 0)
            {
                Label emptyLabel = new Label();
                emptyLabel.Text = "No plugins found in 'Plugins' folder.";
                emptyLabel.AutoSize = true;
                flowLayoutPanel1.Controls.Add(emptyLabel);
            }
        }
    }
}
