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
using System.Text.Json; // Needed for JsonElement and JsonValueKind

namespace newMitre11_29
{
    public partial class Form1 : Form
    {
        // Class-level Fields
        private string _jsonUrl = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";
        private MitreService _mitreService = new MitreService();
        private StixBundle _mitreData;

        private List<StixObject> _tactics;
        // Dictionary key is the Tactic Shortname (e.g., "initial-access") for lookup efficiency
        private Dictionary<string, List<StixObject>> _techniquesByTactic = new Dictionary<string, List<StixObject>>();

        // Define the canonical order of MITRE ATT&CK tactics
        private readonly List<string> _tacticOrder = new List<string>
        {
            "reconnaissance",
            "resource-development",
            "initial-access",
            "execution",
            "persistence",
            "privilege-escalation",
            "defense-evasion",
            "credential-access",
            "discovery",
            "lateral-movement",
            "collection",
            "command-and-control",
            "exfiltration",
            "impact"
        };

        public Form1()
        {
            InitializeComponent();
            _techniquesByTactic = new Dictionary<string, List<StixObject>>();
        }

        // FIXED HELPER METHOD: Extracts phase_name values from kill_chain_phases array
        // The kill_chain_phases is an array of objects like:
        // [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}, ...]
        private List<string> GetTacticNames(JsonElement killChainPhaseElement)
        {
            var names = new List<string>();

            // Check if the JSON element is actually a JSON array
            if (killChainPhaseElement.ValueKind == JsonValueKind.Array)
            {
                // Iterate through the array
                foreach (var element in killChainPhaseElement.EnumerateArray())
                {
                    // Each element is an object with properties like "phase_name"
                    if (element.ValueKind == JsonValueKind.Object)
                    {
                        // Try to get the "phase_name" property from the object
                        if (element.TryGetProperty("phase_name", out JsonElement phaseNameElement))
                        {
                            if (phaseNameElement.ValueKind == JsonValueKind.String)
                            {
                                names.Add(phaseNameElement.GetString());
                            }
                        }
                    }
                }
            }
            return names;
        }

        // ----------------------------------------------------------------

        private void Form1_Load(object sender, EventArgs e)
        {
            // Optional: You could trigger getDataToolStripMenuItem_Click here if you want data loaded at startup
        }

        // Menu: Get Data
        private async void getDataToolStripMenuItem_Click(object sender, EventArgs e)
        {
            richTextBoxScenario.Clear();
            richTextBoxScenario.AppendText("Starting download of MITRE ATT&CK data...\n");
            richTextBoxScenario.Refresh();

            // Use the stored URL (which defaults if not configured)
            _mitreData = await _mitreService.DownloadDataAsync(_jsonUrl);

            if (_mitreData != null)
            {
                // 1. Clear previous data
                checkedListBoxTactics.Items.Clear();
                _techniquesByTactic.Clear();

                // 2. Separate Tactics and Techniques

                // TACTIC FILTERING: Target the specific STIX type for Tactics ("x-mitre-tactic")
                _tactics = _mitreData.objects
                    .Where(o => o.type == "x-mitre-tactic")
                    .ToList();

                // Sort tactics by the canonical order defined in _tacticOrder
                _tactics = _tactics
                    .OrderBy(t =>
                    {
                        int index = _tacticOrder.IndexOf(t.x_mitre_shortname);
                        return index == -1 ? int.MaxValue : index; // Unknown tactics go to the end
                    })
                    .ToList();

                // TECHNIQUES: Filter objects where type is "attack-pattern" and has a kill chain phase array.
                var allTechniques = _mitreData.objects
                    .Where(o => o.type == "attack-pattern" && o.kill_chain_phases.ValueKind == JsonValueKind.Array)
                    .ToList();

                // 3. Populate Tactics CheckedListBox in the correct order
                foreach (var tactic in _tactics)
                {
                    // Display the Tactic Name in the UI
                    checkedListBoxTactics.Items.Add(tactic.name, CheckState.Unchecked);

                    // Initialize the dictionary entry using the Tactic's shortname (the key found in the Techniques)
                    _techniquesByTactic.Add(tactic.x_mitre_shortname, new List<StixObject>());
                }

                // 4. Map Techniques to Tactics
                foreach (var technique in allTechniques)
                {
                    // Use the helper method to safely extract the list of strings (Tactic shortnames)
                    List<string> phaseNames = GetTacticNames(technique.kill_chain_phases);

                    foreach (var phaseName in phaseNames)
                    {
                        // The phaseName (e.g., 'initial-access') matches the dictionary key (x_mitre_shortname).
                        if (_techniquesByTactic.ContainsKey(phaseName))
                        {
                            _techniquesByTactic[phaseName].Add(technique);
                        }
                    }
                }

                // Count total techniques mapped
                int totalTechniques = _techniquesByTactic.Values.Sum(list => list.Count);

                richTextBoxScenario.Clear();
                richTextBoxScenario.AppendText($" Data downloaded successfully!\n\n");
                richTextBoxScenario.AppendText($" Statistics:\n");
                richTextBoxScenario.AppendText($"   • Tactics loaded: {checkedListBoxTactics.Items.Count}\n");
                richTextBoxScenario.AppendText($"   • Total techniques mapped: {totalTechniques}\n\n");
                richTextBoxScenario.AppendText("Select tactics from the list on the left and click 'Create scenario' to generate an attack scenario.\n");
                richTextBoxScenario.AppendText("\n Tactics are displayed in the typical attack sequence order.\n");

                MessageBox.Show($"Data downloaded successfully!\n\nTactics loaded: {checkedListBoxTactics.Items.Count}\nTechniques mapped: {totalTechniques}",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                richTextBoxScenario.Clear();
                richTextBoxScenario.AppendText(" Failed to download data. Please check your internet connection and try again.\n");
            }
        }

        // Menu: File -> Configuration
        private void configurationToolStripMenuItem_Click(object sender, EventArgs e)
        {
            using (var configForm = new ConfigurationForm(_jsonUrl))
            {
                if (configForm.ShowDialog() == DialogResult.OK)
                {
                    _jsonUrl = configForm.JsonUrl;

                    MessageBox.Show(
                        $"ATT&CK JSON URL updated to:\n{_jsonUrl}",
                        "Configuration Saved",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information
                    );
                }
            }
        }

        // Button: Generate Scenario
        private void buttonGenerateScenario_Click(object sender, EventArgs e)
        {
            // 1. Pre-Check: Ensure data is loaded and tactics are present
            if (_mitreData == null || checkedListBoxTactics.Items.Count == 0)
            {
                MessageBox.Show("Please download the ATT&CK data first using the 'Get Data' menu.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var selectedTacticNames = new List<string>();
            // Get the display names (e.g., "Initial Access") of the checked tactics
            foreach (var item in checkedListBoxTactics.CheckedItems)
            {
                selectedTacticNames.Add(item.ToString());
            }

            if (selectedTacticNames.Count == 0)
            {
                MessageBox.Show("Please select at least one Tactic.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var rnd = new Random();
            var scenarioTechniques = new List<StixObject>();

            // 2. Generate the Scenario: Randomly select one technique per selected tactic
            richTextBoxScenario.Clear();
            richTextBoxScenario.AppendText(" Generating Scenario...\n\n");

            foreach (var tacticName in selectedTacticNames)
            {
                // Find the Tactic object using its Display Name to get its Shortname (the Dictionary Key)
                var selectedTactic = _tactics.FirstOrDefault(t => t.name == tacticName);

                if (selectedTactic != null)
                {
                    string tacticKey = selectedTactic.x_mitre_shortname;

                    // Now query the dictionary using the shortname key
                    if (_techniquesByTactic.TryGetValue(tacticKey, out var techniques))
                    {
                        if (techniques.Any())
                        {
                            // Randomly select *one* technique from this tactic
                            var randomIndex = rnd.Next(techniques.Count);
                            scenarioTechniques.Add(techniques[randomIndex]);
                        }
                    }
                }
            }

            // 3. Display the Scenario in RichTextBox
            richTextBoxScenario.Clear();
            richTextBoxScenario.SelectionFont = new Font(richTextBoxScenario.Font, FontStyle.Bold | FontStyle.Underline);
            richTextBoxScenario.AppendText("Generated ATT&CK Scenario\n");
            richTextBoxScenario.SelectionFont = new Font(richTextBoxScenario.Font, FontStyle.Regular);
            richTextBoxScenario.AppendText($"Created: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n\n");

            if (!scenarioTechniques.Any())
            {
                richTextBoxScenario.AppendText(" Could not find techniques for the selected tactics. Data may be incomplete.");
                return;
            }

            foreach (var technique in scenarioTechniques)
            {
                // Get the Tactic Display Name for the chosen technique
                richTextBoxScenario.SelectionFont = new Font(richTextBoxScenario.Font, FontStyle.Bold);

                // Find the Tactic shortname that is common to the technique and the selected list
                List<string> associatedPhases = GetTacticNames(technique.kill_chain_phases);
                var associatedTacticShortName = associatedPhases.FirstOrDefault(tShortName => _tactics.Any(t => t.x_mitre_shortname == tShortName && selectedTacticNames.Contains(t.name)));

                // Find the Tactic display name from the shortname (e.g., "initial-access" -> "Initial Access")
                var associatedTacticDisplayName = _tactics.FirstOrDefault(t => t.x_mitre_shortname == associatedTacticShortName)?.name ?? "Unknown Tactic";

                richTextBoxScenario.AppendText($"Tactic: {associatedTacticDisplayName}\n");

                // Display Technique Name
                richTextBoxScenario.SelectionFont = new Font(richTextBoxScenario.Font, FontStyle.Regular);
                richTextBoxScenario.AppendText($"Technique: {technique.name} ({technique.id})\n");
                richTextBoxScenario.AppendText($"Description: {technique.description}\n");
                richTextBoxScenario.AppendText("___________________________________\n");
            }

            richTextBoxScenario.AppendText($"\n Total techniques in scenario: {scenarioTechniques.Count}\n");
        }

        // Button: Save File
        private void buttonSaveFile_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(richTextBoxScenario.Text))
            {
                MessageBox.Show("The scenario box is empty. Generate a scenario first.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            using (var sfd = new SaveFileDialog())
            {
                sfd.Filter = "Rich Text Format (*.rtf)|*.rtf|Text Files (*.txt)|*.txt";
                sfd.Title = "Save Scenario to File";
                sfd.FileName = $"ATTACK_Scenario_{DateTime.Now:yyyyMMdd_HHmmss}.rtf";

                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        // Save based on file extension
                        if (sfd.FileName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                        {
                            System.IO.File.WriteAllText(sfd.FileName, richTextBoxScenario.Text);
                        }
                        else
                        {
                            // Save the content of the RichTextBox as an RTF file
                            richTextBoxScenario.SaveFile(sfd.FileName, RichTextBoxStreamType.RichText);
                        }
                        MessageBox.Show($"Scenario successfully saved to:\n{sfd.FileName}", "Save Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"An error occurred while saving the file:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            About aboutForm = new About(); // Create an instance of the About form
            aboutForm.ShowDialog(); // Display the About form as a modal dialog
                                    // or aboutForm.Show(); for a modeless dialog
        }
    }
}