using System.Security.Cryptography;
using WSCT.Core.Fluent.Helpers;
using WSCT.GlobalPlatform;
using WSCT.GlobalPlatform.Security;
using WSCT.GUI.Common.Resources.Helpers;
using WSCT.Helpers;
using WSCT.Layers.GlobalPlatform;

namespace WSCT.GUI.Plugins.GlobalPlatform
{
    public partial class Gui : Form
    {
        public Gui()
        {
            InitializeComponent();

            _guiIsGlobalPlatformActive.Checked = GlobalPlatformController.IsLayerActive;

            _guiKEnc.Text = GlobalPlatformController.CardKeys.Enc.ToHexa();
            _guiKMac.Text = GlobalPlatformController.CardKeys.Mac.ToHexa();
            _guiKDek.Text = GlobalPlatformController.CardKeys.Dek.ToHexa();

            _guiSecurityDomain.Text = GlobalPlatformController.SecurityDomainAid.Aid.ToHexa();
            _guiKeyIdentifier.Text = GlobalPlatformController.KeyIdentifier.ToString("X2");
            _guiKeyVersion.Text = GlobalPlatformController.KeyVersion.ToString("X2");
        }

        #region >> *_Checked

        private void GuiIsGlobalPlatformActive_CheckedChanged(object sender, EventArgs e)
        {
            GlobalPlatformController.IsLayerActive = _guiIsGlobalPlatformActive.Checked;
        }

        #endregion

        #region >> *Click

        private void GuiGetCardData_Click(object sender, EventArgs eventArgs)
        {
            GlobalPlatformController.GpCard = new GlobalPlatformCard(GlobalPlatformController.NextChannelLayer);

            GlobalPlatformController.GpCard.ProcessGetCardData()
                .ThrowIfNotSuccess()
                .ThrowIfSWNot9000();

            // TODO: Update the GUI accordingly.
        }

        private void GuiAuthenticate_Click(object sender, EventArgs eventArgs)
        {
            var scpUsed = GlobalPlatformController.GpCard.CardData.SupportedScps.First();

            var hostChallenge = RandomNumberGenerator.GetBytes(8);

            // INITIALIZE UPDATE
            GlobalPlatformController.GpCard
                .ProcessInitializeUpdate(scpUsed, GlobalPlatformController.KeyVersion, GlobalPlatformController.KeyIdentifier, hostChallenge)
                .ThrowIfNotSuccess()
                .ThrowIfSWNot9000();

            GlobalPlatformController.GpCard
                .CreateSessionKeys(GlobalPlatformController.CardKeys);

            GlobalPlatformController.GpCard
                .AuthenticateCard();

            GlobalPlatformController.GpCard
                .ProcessExternalAuthenticate(SecurityLevel.CMac | SecurityLevel.CDecryption)
                .ThrowIfNotSuccess()
                .ThrowIfSWNot9000();

            // TODO: Update the GUI accordingly.
        }

        #endregion

        #region >> *TextChanged

        private void GuiKDek_TextChanged(object sender, EventArgs eventArgs)
        {
            try
            {
                var kDek = _guiKDek.Text.FromHexa();
                _guiKDek.ResetControlBackColor();

                GlobalPlatformController.CardKeys = new WSCT.GlobalPlatform.Security.Keys(
                    GlobalPlatformController.CardKeys.Enc,
                    GlobalPlatformController.CardKeys.Mac,
                    kDek);
            }
            catch (Exception)
            {
                _guiKDek.SetControlBackColor(Common.Resources.Colors.StatusError);
            }
        }

        private void GuiKEnc_TextChanged(object sender, EventArgs eventArgs)
        {
            try
            {
                var kEnc = _guiKEnc.Text.FromHexa();
                _guiKEnc.ResetControlBackColor();

                GlobalPlatformController.CardKeys = new WSCT.GlobalPlatform.Security.Keys(
                    kEnc,
                    GlobalPlatformController.CardKeys.Mac,
                    GlobalPlatformController.CardKeys.Dek);
            }
            catch (Exception)
            {
                _guiKEnc.SetControlBackColor(Common.Resources.Colors.StatusError);
            }
        }

        private void GuiKeyIdentifier_TextChanged(object sender, EventArgs eventArgs)
        {
            try
            {
                GlobalPlatformController.KeyIdentifier = _guiKeyIdentifier.Text.FromHexa().First();
                _guiKeyIdentifier.ResetControlBackColor();
            }
            catch (Exception)
            {
                _guiKeyIdentifier.SetControlBackColor(Common.Resources.Colors.StatusError);
            }
        }

        private void GuiKeyVersion_TextChanged(object sender, EventArgs eventArgs)
        {
            try
            {
                GlobalPlatformController.KeyVersion = _guiKeyVersion.Text.FromHexa().First();
                _guiKeyVersion.ResetControlBackColor();
            }
            catch (Exception)
            {
                _guiKeyVersion.SetControlBackColor(Common.Resources.Colors.StatusError);
            }
        }

        private void GuiKMac_TextChanged(object sender, EventArgs eventArgs)
        {
            try
            {
                var kMac = _guiKMac.Text.FromHexa();
                _guiKMac.ResetControlBackColor();

                GlobalPlatformController.CardKeys = new WSCT.GlobalPlatform.Security.Keys(
                    GlobalPlatformController.CardKeys.Enc,
                    kMac,
                    GlobalPlatformController.CardKeys.Dek);
            }
            catch (Exception)
            {
                _guiKMac.SetControlBackColor(Common.Resources.Colors.StatusError);
            }
        }

        private void GuiSecurityDomain_TextChanged(object sender, EventArgs eventArgs)
        {
            try
            {
                GlobalPlatformController.SecurityDomainAid = new WSCT.GlobalPlatform.AID(_guiSecurityDomain.Text.FromHexa());
                _guiSecurityDomain.ResetControlBackColor();
            }
            catch (Exception)
            {
                _guiSecurityDomain.SetControlBackColor(Common.Resources.Colors.StatusError);
            }
        }

        #endregion
    }
}
