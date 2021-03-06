﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MeshCentralRouter
{
    public partial class DeviceSettingsForm : Form
    {
        public DeviceSettingsForm()
        {
            InitializeComponent();
            doubleClickComboBox.SelectedIndex = 0;
        }

        public int deviceDoubleClickAction
        {
            get { return doubleClickComboBox.SelectedIndex; }
            set { doubleClickComboBox.SelectedIndex = value; }
        }

        public bool ShowSystemTray
        {
            get { return systemTrayCheckBox.Checked; }
            set { systemTrayCheckBox.Checked = value; }
        }

        private void okButton_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.OK;
        }
    }
}
