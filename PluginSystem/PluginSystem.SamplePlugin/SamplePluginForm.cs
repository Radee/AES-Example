using System;
using System.Windows.Forms;

namespace PluginSystem.SamplePlugin
{
    public partial class SamplePluginForm : Form
    {
        public SamplePluginForm()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            this.Close();
        }
    }
}
