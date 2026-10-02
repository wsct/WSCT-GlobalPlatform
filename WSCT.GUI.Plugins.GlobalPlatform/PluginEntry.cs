using WSCT.GUI.Plugins.GlobalPlatform.Resources;

namespace WSCT.GUI.Plugins.GlobalPlatform;

/// <summary>
/// 
/// </summary>
[PluginEntry(Name = nameof(Lang.PluginName), Description = nameof(Lang.PluginDescription), ResourceType = typeof(Lang))]
public class PluginEntry : GenericPluginEntry<Gui>
{
}