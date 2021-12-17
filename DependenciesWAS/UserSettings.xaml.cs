using Dependencies.Properties;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Dependencies
{
	public sealed partial class UserSettings : UserControl, INotifyPropertyChanged
	{
		public UserSettings()
		{
			this.InitializeComponent();

			TreeBuildCombo.ItemsSource = Enum.GetValues(typeof(TreeBuildingBehaviour.DependencyTreeBehaviour));
			BinaryCacheCombo.ItemsSource = Enum.GetValues(typeof(BinaryCacheOption.BinaryCacheOptionValue));
		}

		void OnPropertyChanged([CallerMemberName] string propertyName = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		bool BinaryCacheOptionValueSetting { get => Settings.Default.BinaryCacheOptionValue; set { if (value != Settings.Default.BinaryCacheOptionValue) { Settings.Default.BinaryCacheOptionValue = value; OnPropertyChanged(); FindName(nameof(UpdateNote)); } } }

		string TreeBuildBehaviourSetting { get => Settings.Default.TreeBuildBehaviour; set { if (value != Settings.Default.TreeBuildBehaviour) { Settings.Default.TreeBuildBehaviour = value; OnPropertyChanged(); } } }

		int TreeDepthSetting { get => Settings.Default.TreeDepth; set { if (value != Settings.Default.TreeDepth) { Settings.Default.TreeDepth = value; OnPropertyChanged(); } } }

		public event PropertyChangedEventHandler PropertyChanged;
	}
}
