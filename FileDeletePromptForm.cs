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
    public partial class FileDeletePromptForm : Form
    {
        public FileDeletePromptForm(string message, bool rec)
        {
            InitializeComponent();
            mainLabel.Text = message;
            if (rec == false)
            {
                recursiveCheckBox.Visible = false;
                Height = 142;
            }
        }

        public bool recursive { get { return recursiveCheckBox.Checked; } }

        private void okButton_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.OK;
        }

        private void cancelButton_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.Cancel;
        }
    }
}
