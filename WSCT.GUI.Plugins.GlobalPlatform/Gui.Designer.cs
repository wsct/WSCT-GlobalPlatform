namespace WSCT.GUI.Plugins.GlobalPlatform
{
    partial class Gui
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            TextBox CC4ManagerLabel;
            _guiGetCardData = new Button();
            _guiAuthenticate = new Button();
            _guiKEnc = new TextBox();
            CardKeyLabel = new Label();
            _guiKMac = new TextBox();
            label1 = new Label();
            _guiKDek = new TextBox();
            label2 = new Label();
            ConfigurationZone = new GroupBox();
            _guiIsGlobalPlatformActive = new CheckBox();
            groupBox1 = new GroupBox();
            guiKeyVersionLabel = new Label();
            _guiKeyVersion = new TextBox();
            guiKeyIdentifierLabel = new Label();
            _guiKeyIdentifier = new TextBox();
            groupBox2 = new GroupBox();
            _guiSecurityDomainLabel = new Label();
            _guiSecurityDomain = new TextBox();
            CC4ManagerLabel = new TextBox();
            ConfigurationZone.SuspendLayout();
            groupBox1.SuspendLayout();
            groupBox2.SuspendLayout();
            SuspendLayout();
            // 
            // CC4ManagerLabel
            // 
            CC4ManagerLabel.BackColor = SystemColors.Control;
            CC4ManagerLabel.BorderStyle = BorderStyle.None;
            CC4ManagerLabel.Location = new Point(7, 49);
            CC4ManagerLabel.Margin = new Padding(3, 4, 3, 4);
            CC4ManagerLabel.Multiline = true;
            CC4ManagerLabel.Name = "CC4ManagerLabel";
            CC4ManagerLabel.Size = new Size(412, 17);
            CC4ManagerLabel.TabIndex = 1;
            CC4ManagerLabel.Text = "▷ allows handling of GlobalPlatform compliant cards";
            // 
            // _guiGetCardData
            // 
            _guiGetCardData.Location = new Point(452, 22);
            _guiGetCardData.Margin = new Padding(2);
            _guiGetCardData.Name = "_guiGetCardData";
            _guiGetCardData.Size = new Size(129, 25);
            _guiGetCardData.TabIndex = 0;
            _guiGetCardData.Text = "Get Card Data";
            _guiGetCardData.UseVisualStyleBackColor = true;
            _guiGetCardData.Click += GuiGetCardData_Click;
            // 
            // _guiAuthenticate
            // 
            _guiAuthenticate.Location = new Point(452, 86);
            _guiAuthenticate.Margin = new Padding(2);
            _guiAuthenticate.Name = "_guiAuthenticate";
            _guiAuthenticate.Size = new Size(130, 25);
            _guiAuthenticate.TabIndex = 1;
            _guiAuthenticate.Text = "Authenticate";
            _guiAuthenticate.UseVisualStyleBackColor = true;
            _guiAuthenticate.Click += GuiAuthenticate_Click;
            // 
            // _guiKEnc
            // 
            _guiKEnc.Font = new Font("Fira Code", 7.999999F, FontStyle.Regular, GraphicsUnit.Point, 0);
            _guiKEnc.Location = new Point(73, 41);
            _guiKEnc.Margin = new Padding(2);
            _guiKEnc.Name = "_guiKEnc";
            _guiKEnc.Size = new Size(344, 21);
            _guiKEnc.TabIndex = 5;
            _guiKEnc.Text = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
            _guiKEnc.TextChanged += GuiKEnc_TextChanged;
            // 
            // CardKeyLabel
            // 
            CardKeyLabel.AutoSize = true;
            CardKeyLabel.Font = new Font("Microsoft Sans Serif", 8F, FontStyle.Bold, GraphicsUnit.Point, 0);
            CardKeyLabel.Location = new Point(5, 43);
            CardKeyLabel.Margin = new Padding(2, 0, 2, 0);
            CardKeyLabel.Name = "CardKeyLabel";
            CardKeyLabel.Size = new Size(41, 13);
            CardKeyLabel.TabIndex = 4;
            CardKeyLabel.Text = "KEnc:";
            // 
            // _guiKMac
            // 
            _guiKMac.Font = new Font("Fira Code", 7.999999F, FontStyle.Regular, GraphicsUnit.Point, 0);
            _guiKMac.Location = new Point(75, 66);
            _guiKMac.Margin = new Padding(2);
            _guiKMac.Name = "_guiKMac";
            _guiKMac.Size = new Size(344, 21);
            _guiKMac.TabIndex = 7;
            _guiKMac.Text = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
            _guiKMac.TextChanged += GuiKMac_TextChanged;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Font = new Font("Microsoft Sans Serif", 8F, FontStyle.Bold, GraphicsUnit.Point, 0);
            label1.Location = new Point(5, 68);
            label1.Margin = new Padding(2, 0, 2, 0);
            label1.Name = "label1";
            label1.Size = new Size(43, 13);
            label1.TabIndex = 6;
            label1.Text = "KMac:";
            // 
            // _guiKDek
            // 
            _guiKDek.Font = new Font("Fira Code", 7.999999F, FontStyle.Regular, GraphicsUnit.Point, 0);
            _guiKDek.Location = new Point(75, 91);
            _guiKDek.Margin = new Padding(2);
            _guiKDek.Name = "_guiKDek";
            _guiKDek.Size = new Size(344, 21);
            _guiKDek.TabIndex = 9;
            _guiKDek.Text = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
            _guiKDek.TextChanged += GuiKDek_TextChanged;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Font = new Font("Microsoft Sans Serif", 8F, FontStyle.Bold, GraphicsUnit.Point, 0);
            label2.Location = new Point(5, 93);
            label2.Margin = new Padding(2, 0, 2, 0);
            label2.Name = "label2";
            label2.Size = new Size(42, 13);
            label2.TabIndex = 8;
            label2.Text = "KDec:";
            // 
            // ConfigurationZone
            // 
            ConfigurationZone.AutoSize = true;
            ConfigurationZone.Controls.Add(CC4ManagerLabel);
            ConfigurationZone.Controls.Add(_guiIsGlobalPlatformActive);
            ConfigurationZone.Location = new Point(9, 9);
            ConfigurationZone.Margin = new Padding(3, 4, 3, 4);
            ConfigurationZone.Name = "ConfigurationZone";
            ConfigurationZone.Padding = new Padding(3, 4, 3, 4);
            ConfigurationZone.Size = new Size(587, 90);
            ConfigurationZone.TabIndex = 10;
            ConfigurationZone.TabStop = false;
            ConfigurationZone.Text = "Stack Configuration";
            // 
            // _guiIsGlobalPlatformActive
            // 
            _guiIsGlobalPlatformActive.AutoSize = true;
            _guiIsGlobalPlatformActive.Font = new Font("Microsoft Sans Serif", 8.25F, FontStyle.Bold, GraphicsUnit.Point, 0);
            _guiIsGlobalPlatformActive.Location = new Point(8, 23);
            _guiIsGlobalPlatformActive.Margin = new Padding(3, 4, 3, 4);
            _guiIsGlobalPlatformActive.Name = "_guiIsGlobalPlatformActive";
            _guiIsGlobalPlatformActive.Size = new Size(161, 17);
            _guiIsGlobalPlatformActive.TabIndex = 0;
            _guiIsGlobalPlatformActive.Text = "GlobalPlatform Manager";
            _guiIsGlobalPlatformActive.UseVisualStyleBackColor = true;
            _guiIsGlobalPlatformActive.CheckedChanged += GuiIsGlobalPlatformActive_CheckedChanged;
            // 
            // groupBox1
            // 
            groupBox1.AutoSize = true;
            groupBox1.Controls.Add(guiKeyVersionLabel);
            groupBox1.Controls.Add(_guiKeyVersion);
            groupBox1.Controls.Add(guiKeyIdentifierLabel);
            groupBox1.Controls.Add(_guiKeyIdentifier);
            groupBox1.Controls.Add(_guiAuthenticate);
            groupBox1.Controls.Add(CardKeyLabel);
            groupBox1.Controls.Add(_guiKEnc);
            groupBox1.Controls.Add(_guiKDek);
            groupBox1.Controls.Add(label1);
            groupBox1.Controls.Add(label2);
            groupBox1.Controls.Add(_guiKMac);
            groupBox1.Location = new Point(9, 181);
            groupBox1.Margin = new Padding(3, 4, 3, 4);
            groupBox1.Name = "groupBox1";
            groupBox1.Padding = new Padding(3, 4, 3, 4);
            groupBox1.Size = new Size(587, 134);
            groupBox1.TabIndex = 11;
            groupBox1.TabStop = false;
            groupBox1.Text = "Card Keys";
            // 
            // guiKeyVersionLabel
            // 
            guiKeyVersionLabel.AutoSize = true;
            guiKeyVersionLabel.Font = new Font("Microsoft Sans Serif", 8F, FontStyle.Bold, GraphicsUnit.Point, 0);
            guiKeyVersionLabel.Location = new Point(102, 18);
            guiKeyVersionLabel.Margin = new Padding(2, 0, 2, 0);
            guiKeyVersionLabel.Name = "guiKeyVersionLabel";
            guiKeyVersionLabel.Size = new Size(53, 13);
            guiKeyVersionLabel.TabIndex = 12;
            guiKeyVersionLabel.Text = "Version:";
            // 
            // _guiKeyVersion
            // 
            _guiKeyVersion.Font = new Font("Fira Code", 7.999999F, FontStyle.Regular, GraphicsUnit.Point, 0);
            _guiKeyVersion.Location = new Point(159, 16);
            _guiKeyVersion.Margin = new Padding(2);
            _guiKeyVersion.MaxLength = 2;
            _guiKeyVersion.Name = "_guiKeyVersion";
            _guiKeyVersion.Size = new Size(25, 21);
            _guiKeyVersion.TabIndex = 13;
            _guiKeyVersion.Text = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
            _guiKeyVersion.TextChanged += GuiKeyVersion_TextChanged;
            // 
            // guiKeyIdentifierLabel
            // 
            guiKeyIdentifierLabel.AutoSize = true;
            guiKeyIdentifierLabel.Font = new Font("Microsoft Sans Serif", 8F, FontStyle.Bold, GraphicsUnit.Point, 0);
            guiKeyIdentifierLabel.Location = new Point(8, 18);
            guiKeyIdentifierLabel.Margin = new Padding(2, 0, 2, 0);
            guiKeyIdentifierLabel.Name = "guiKeyIdentifierLabel";
            guiKeyIdentifierLabel.Size = new Size(61, 13);
            guiKeyIdentifierLabel.TabIndex = 10;
            guiKeyIdentifierLabel.Text = "Identifier:";
            // 
            // _guiKeyIdentifier
            // 
            _guiKeyIdentifier.Font = new Font("Fira Code", 7.999999F, FontStyle.Regular, GraphicsUnit.Point, 0);
            _guiKeyIdentifier.Location = new Point(73, 16);
            _guiKeyIdentifier.Margin = new Padding(2);
            _guiKeyIdentifier.MaxLength = 2;
            _guiKeyIdentifier.Name = "_guiKeyIdentifier";
            _guiKeyIdentifier.Size = new Size(25, 21);
            _guiKeyIdentifier.TabIndex = 11;
            _guiKeyIdentifier.Text = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
            _guiKeyIdentifier.TextChanged += GuiKeyIdentifier_TextChanged;
            // 
            // groupBox2
            // 
            groupBox2.AutoSize = true;
            groupBox2.Controls.Add(_guiSecurityDomainLabel);
            groupBox2.Controls.Add(_guiSecurityDomain);
            groupBox2.Controls.Add(_guiGetCardData);
            groupBox2.Location = new Point(9, 104);
            groupBox2.Margin = new Padding(3, 4, 3, 4);
            groupBox2.Name = "groupBox2";
            groupBox2.Padding = new Padding(3, 4, 3, 4);
            groupBox2.Size = new Size(587, 69);
            groupBox2.TabIndex = 12;
            groupBox2.TabStop = false;
            groupBox2.Text = "Card Status";
            // 
            // _guiSecurityDomainLabel
            // 
            _guiSecurityDomainLabel.AutoSize = true;
            _guiSecurityDomainLabel.Font = new Font("Microsoft Sans Serif", 8F, FontStyle.Bold, GraphicsUnit.Point, 0);
            _guiSecurityDomainLabel.Location = new Point(5, 20);
            _guiSecurityDomainLabel.Margin = new Padding(2, 0, 2, 0);
            _guiSecurityDomainLabel.Name = "_guiSecurityDomainLabel";
            _guiSecurityDomainLabel.Size = new Size(103, 13);
            _guiSecurityDomainLabel.TabIndex = 13;
            _guiSecurityDomainLabel.Text = "Security Domain:";
            // 
            // _guiSecurityDomain
            // 
            _guiSecurityDomain.Font = new Font("Fira Code", 7.999999F, FontStyle.Regular, GraphicsUnit.Point, 0);
            _guiSecurityDomain.Location = new Point(112, 18);
            _guiSecurityDomain.Margin = new Padding(2);
            _guiSecurityDomain.Name = "_guiSecurityDomain";
            _guiSecurityDomain.Size = new Size(173, 21);
            _guiSecurityDomain.TabIndex = 14;
            _guiSecurityDomain.Text = "A0 00 00 00 00 00";
            _guiSecurityDomain.TextChanged += GuiSecurityDomain_TextChanged;
            // 
            // Gui
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(605, 322);
            Controls.Add(groupBox2);
            Controls.Add(groupBox1);
            Controls.Add(ConfigurationZone);
            Margin = new Padding(2);
            Name = "Gui";
            Text = "GlobalPlatform for WSCT";
            ConfigurationZone.ResumeLayout(false);
            ConfigurationZone.PerformLayout();
            groupBox1.ResumeLayout(false);
            groupBox1.PerformLayout();
            groupBox2.ResumeLayout(false);
            groupBox2.PerformLayout();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Button _guiGetCardData;
        private Button _guiAuthenticate;
        private TextBox _guiKEnc;
        private Label CardKeyLabel;
        private TextBox _guiKMac;
        private Label label1;
        private TextBox _guiKDek;
        private Label label2;
        private GroupBox ConfigurationZone;
        private CheckBox _guiIsGlobalPlatformActive;
        private GroupBox groupBox1;
        private GroupBox groupBox2;
        private Label guiKeyIdentifierLabel;
        private Label guiKeyVersionLabel;
        private TextBox _guiKeyVersion;
        private TextBox _guiKeyIdentifier;
        private Label _guiSecurityDomainLabel;
        private TextBox _guiSecurityDomain;
    }
}