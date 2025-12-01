/*
 * MIT License
 * 
 * Copyright (c) 2025 Kenneth Ray
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * Author: Kenneth Ray
 * Version: 1.0b
 */
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace newMitre11_29
{
    public partial class ConfigurationForm : Form
    {
        // 1. Property to hold the URL that will be passed back to Form1
        public string JsonUrl { get; private set; }

        // 2. The known default URL for MITRE ATT&CK data
        private const string DefaultUrl = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

        // 3. The CORRECT constructor that accepts the current URL
        public ConfigurationForm(string currentUrl)
        {
            InitializeComponent();

            // Populate the textbox (textBoxJsonUrl) with the current URL passed in
            // If the passed URL is blank or null, use the hardcoded DefaultUrl instead.
            textBoxJsonUrl.Text = string.IsNullOrEmpty(currentUrl) ? DefaultUrl : currentUrl;

            // Initialize the public property with the current value
            JsonUrl = currentUrl;
        }

        // NOTE: The empty ConfigurationForm() constructor was removed to fix the 'currentUrl' error.

        // 4. Handles the "Save" button click
        private void buttonSave_Click(object sender, EventArgs e)
        {
            // Set the public property (JsonUrl) to the text currently in the textbox
            JsonUrl = textBoxJsonUrl.Text;

            // Set the dialog result to OK and close the form
            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        // 5. Handles the "Cancel" button click
        private void buttonCancel_Click(object sender, EventArgs e)
        {
            // Set the dialog result to Cancel and close the form.
            // JsonUrl remains unchanged.
            this.DialogResult = DialogResult.Cancel;
            this.Close();
        }

        // This event handler is usually not needed for a simple config form, 
        // but it's kept here if the designer created it.
        private void ConfigurationForm_Load(object sender, EventArgs e)
        {
            // No code needed here for this implementation.
        }
    }
}