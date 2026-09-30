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
            guiGetCardData = new Button();
            guiAuthenticate = new Button();
            CardKeyValue = new TextBox();
            CardKeyLabel = new Label();
            textBox1 = new TextBox();
            label1 = new Label();
            textBox2 = new TextBox();
            label2 = new Label();
            ConfigurationZone = new GroupBox();
            checkBox1 = new CheckBox();
            groupBox1 = new GroupBox();
            guiKeyVersionLabel = new Label();
            guiKeyVersion = new TextBox();
            guiKeyIdentifierLabel = new Label();
            guiKeyIdentifier = new TextBox();
            groupBox2 = new GroupBox();
            label3 = new Label();
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
            CC4ManagerLabel.Location = new Point(10, 81);
            CC4ManagerLabel.Margin = new Padding(4, 6, 4, 6);
            CC4ManagerLabel.Multiline = true;
            CC4ManagerLabel.Name = "CC4ManagerLabel";
            CC4ManagerLabel.Size = new Size(589, 29);
            CC4ManagerLabel.TabIndex = 1;
            CC4ManagerLabel.Text = "▷ allows handling of GlobalPlatform compliant cards";
            // 
            // guiGetCardData
            // 
            guiGetCardData.Location = new Point(7, 33);
            guiGetCardData.Name = "guiGetCardData";
            guiGetCardData.Size = new Size(189, 34);
            guiGetCardData.TabIndex = 0;
            guiGetCardData.Text = "Get Card Data";
            guiGetCardData.UseVisualStyleBackColor = true;
            // 
            // guiAuthenticate
            // 
            guiAuthenticate.Location = new Point(11, 167);
            guiAuthenticate.Name = "guiAuthenticate";
            guiAuthenticate.Size = new Size(185, 34);
            guiAuthenticate.TabIndex = 1;
            guiAuthenticate.Text = "Authenticate";
            guiAuthenticate.UseVisualStyleBackColor = true;
            // 
            // CardKeyValue
            // 
            CardKeyValue.Font = new Font("Fira Code", 7.999999F, FontStyle.Regular, GraphicsUnit.Point, 0);
            CardKeyValue.Location = new Point(103, 63);
            CardKeyValue.Margin = new Padding(3, 4, 3, 4);
            CardKeyValue.Name = "CardKeyValue";
            CardKeyValue.Size = new Size(490, 27);
            CardKeyValue.TabIndex = 5;
            CardKeyValue.Text = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
            // 
            // CardKeyLabel
            // 
            CardKeyLabel.AutoSize = true;
            CardKeyLabel.Font = new Font("Microsoft Sans Serif", 8F, FontStyle.Bold, GraphicsUnit.Point, 0);
            CardKeyLabel.Location = new Point(11, 65);
            CardKeyLabel.Name = "CardKeyLabel";
            CardKeyLabel.Size = new Size(56, 20);
            CardKeyLabel.TabIndex = 4;
            CardKeyLabel.Text = "KEnc:";
            // 
            // textBox1
            // 
            textBox1.Font = new Font("Fira Code", 7.999999F, FontStyle.Regular, GraphicsUnit.Point, 0);
            textBox1.Location = new Point(103, 98);
            textBox1.Margin = new Padding(3, 4, 3, 4);
            textBox1.Name = "textBox1";
            textBox1.Size = new Size(490, 27);
            textBox1.TabIndex = 7;
            textBox1.Text = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Font = new Font("Microsoft Sans Serif", 8F, FontStyle.Bold, GraphicsUnit.Point, 0);
            label1.Location = new Point(11, 100);
            label1.Name = "label1";
            label1.Size = new Size(58, 20);
            label1.TabIndex = 6;
            label1.Text = "KMac:";
            // 
            // textBox2
            // 
            textBox2.Font = new Font("Fira Code", 7.999999F, FontStyle.Regular, GraphicsUnit.Point, 0);
            textBox2.Location = new Point(103, 133);
            textBox2.Margin = new Padding(3, 4, 3, 4);
            textBox2.Name = "textBox2";
            textBox2.Size = new Size(490, 27);
            textBox2.TabIndex = 9;
            textBox2.Text = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Font = new Font("Microsoft Sans Serif", 8F, FontStyle.Bold, GraphicsUnit.Point, 0);
            label2.Location = new Point(11, 135);
            label2.Name = "label2";
            label2.Size = new Size(57, 20);
            label2.TabIndex = 8;
            label2.Text = "KDec:";
            // 
            // ConfigurationZone
            // 
            ConfigurationZone.AutoSize = true;
            ConfigurationZone.Controls.Add(CC4ManagerLabel);
            ConfigurationZone.Controls.Add(checkBox1);
            ConfigurationZone.Location = new Point(13, 15);
            ConfigurationZone.Margin = new Padding(4, 6, 4, 6);
            ConfigurationZone.Name = "ConfigurationZone";
            ConfigurationZone.Padding = new Padding(4, 6, 4, 6);
            ConfigurationZone.Size = new Size(838, 146);
            ConfigurationZone.TabIndex = 10;
            ConfigurationZone.TabStop = false;
            ConfigurationZone.Text = "Stack Configuration";
            // 
            // checkBox1
            // 
            checkBox1.AutoSize = true;
            checkBox1.Font = new Font("Microsoft Sans Serif", 8.25F, FontStyle.Bold, GraphicsUnit.Point, 0);
            checkBox1.Location = new Point(11, 39);
            checkBox1.Margin = new Padding(4, 6, 4, 6);
            checkBox1.Name = "checkBox1";
            checkBox1.Size = new Size(238, 24);
            checkBox1.TabIndex = 0;
            checkBox1.Text = "GlobalPlatform Manager";
            checkBox1.UseVisualStyleBackColor = true;
            // 
            // groupBox1
            // 
            groupBox1.AutoSize = true;
            groupBox1.Controls.Add(guiKeyVersionLabel);
            groupBox1.Controls.Add(guiKeyVersion);
            groupBox1.Controls.Add(guiKeyIdentifierLabel);
            groupBox1.Controls.Add(guiKeyIdentifier);
            groupBox1.Controls.Add(guiAuthenticate);
            groupBox1.Controls.Add(CardKeyLabel);
            groupBox1.Controls.Add(CardKeyValue);
            groupBox1.Controls.Add(textBox2);
            groupBox1.Controls.Add(label1);
            groupBox1.Controls.Add(label2);
            groupBox1.Controls.Add(textBox1);
            groupBox1.Location = new Point(13, 285);
            groupBox1.Margin = new Padding(4, 6, 4, 6);
            groupBox1.Name = "groupBox1";
            groupBox1.Padding = new Padding(4, 6, 4, 6);
            groupBox1.Size = new Size(839, 234);
            groupBox1.TabIndex = 11;
            groupBox1.TabStop = false;
            groupBox1.Text = "Card Keys";
            // 
            // guiKeyVersionLabel
            // 
            guiKeyVersionLabel.AutoSize = true;
            guiKeyVersionLabel.Font = new Font("Microsoft Sans Serif", 8F, FontStyle.Bold, GraphicsUnit.Point, 0);
            guiKeyVersionLabel.Location = new Point(143, 30);
            guiKeyVersionLabel.Name = "guiKeyVersionLabel";
            guiKeyVersionLabel.Size = new Size(75, 20);
            guiKeyVersionLabel.TabIndex = 12;
            guiKeyVersionLabel.Text = "Version:";
            // 
            // guiKeyVersion
            // 
            guiKeyVersion.Font = new Font("Fira Code", 7.999999F, FontStyle.Regular, GraphicsUnit.Point, 0);
            guiKeyVersion.Location = new Point(224, 28);
            guiKeyVersion.Margin = new Padding(3, 4, 3, 4);
            guiKeyVersion.Name = "guiKeyVersion";
            guiKeyVersion.Size = new Size(34, 27);
            guiKeyVersion.TabIndex = 13;
            guiKeyVersion.Text = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
            // 
            // guiKeyIdentifierLabel
            // 
            guiKeyIdentifierLabel.AutoSize = true;
            guiKeyIdentifierLabel.Font = new Font("Microsoft Sans Serif", 8F, FontStyle.Bold, GraphicsUnit.Point, 0);
            guiKeyIdentifierLabel.Location = new Point(11, 30);
            guiKeyIdentifierLabel.Name = "guiKeyIdentifierLabel";
            guiKeyIdentifierLabel.Size = new Size(86, 20);
            guiKeyIdentifierLabel.TabIndex = 10;
            guiKeyIdentifierLabel.Text = "Identifier:";
            // 
            // guiKeyIdentifier
            // 
            guiKeyIdentifier.Font = new Font("Fira Code", 7.999999F, FontStyle.Regular, GraphicsUnit.Point, 0);
            guiKeyIdentifier.Location = new Point(103, 28);
            guiKeyIdentifier.Margin = new Padding(3, 4, 3, 4);
            guiKeyIdentifier.Name = "guiKeyIdentifier";
            guiKeyIdentifier.Size = new Size(34, 27);
            guiKeyIdentifier.TabIndex = 11;
            guiKeyIdentifier.Text = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00";
            // 
            // groupBox2
            // 
            groupBox2.AutoSize = true;
            groupBox2.Controls.Add(label3);
            groupBox2.Controls.Add(guiGetCardData);
            groupBox2.Location = new Point(13, 173);
            groupBox2.Margin = new Padding(4, 6, 4, 6);
            groupBox2.Name = "groupBox2";
            groupBox2.Padding = new Padding(4, 6, 4, 6);
            groupBox2.Size = new Size(838, 100);
            groupBox2.TabIndex = 12;
            groupBox2.TabStop = false;
            groupBox2.Text = "Card Status";
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Font = new Font("Microsoft Sans Serif", 8F, FontStyle.Bold, GraphicsUnit.Point, 0);
            label3.Location = new Point(198, 42);
            label3.Name = "label3";
            label3.Size = new Size(138, 20);
            label3.TabIndex = 5;
            label3.Text = "Supported SCP:";
            // 
            // Gui
            // 
            AutoScaleDimensions = new SizeF(10F, 25F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(864, 532);
            Controls.Add(groupBox2);
            Controls.Add(groupBox1);
            Controls.Add(ConfigurationZone);
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

        private Button guiGetCardData;
        private Button guiAuthenticate;
        private TextBox CardKeyValue;
        private Label CardKeyLabel;
        private TextBox textBox1;
        private Label label1;
        private TextBox textBox2;
        private Label label2;
        private GroupBox ConfigurationZone;
        private CheckBox checkBox1;
        private GroupBox groupBox1;
        private GroupBox groupBox2;
        private Label guiKeyIdentifierLabel;
        private Label guiKeyVersionLabel;
        private TextBox guiKeyVersion;
        private TextBox guiKeyIdentifier;
        private Label label3;
    }
}