using Dependencies.Properties;
using Microsoft.Graphics.Canvas.Text;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using Windows.Storage;
using Windows.Storage.Pickers;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Dependencies
{
	public sealed partial class UserSettings : UserControl, INotifyPropertyChanged
	{
		public UserSettings()
		{
			SortedFonts = new Toolkit.Uwp.UI.AdvancedCollectionView(Fonts, true);
			SortedFonts.SortDescriptions.Add(new CommunityToolkit.WinUI.UI.SortDescription(null, CommunityToolkit.WinUI.UI.SortDirection.Ascending));

			this.InitializeComponent();

			TreeBuildCombo.ItemsSource = Enum.GetValues(typeof(TreeBuildingBehaviour.DependencyTreeBehaviour));
			BinaryCacheCombo.ItemsSource = Enum.GetValues(typeof(BinaryCacheOption.BinaryCacheOptionValue));


			// Get list of usable fonts
			string[] fonts = CanvasTextFormat.GetSystemFontFamilies();
			CanvasFontSet fontSet = CanvasFontSet.GetSystemFontSet();

			using (SortedFonts.DeferRefresh())
			{
				foreach (var font in fonts)
				{
					CanvasFontSet matchingSet = fontSet.GetMatchingFonts(font, FontWeights.Normal, Windows.UI.Text.FontStretch.Normal, Windows.UI.Text.FontStyle.Normal);
					if (matchingSet.Fonts.Count > 0)
					{
						CanvasFontFace matchingFont = matchingSet.Fonts.FirstOrDefault();
						if (!matchingFont.IsSymbolFont)
						{
							Fonts.Add(font);
						}
					}
				}
			}
			if(SortedFonts.Contains(Settings.Default.Font))
			{
				FontBox.SelectedItem = Settings.Default.Font;
			}
		}

		private async void OnPeviewerPathSettingChange(object sender, RoutedEventArgs e)
		{
			string programPath = Dependencies.Properties.Settings.Default.PeViewerPath;

			FileOpenPicker loadPicker = new FileOpenPicker();

			loadPicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
			loadPicker.SettingsIdentifier = "PeViewerPath";
			loadPicker.FileTypeFilter.Add(".exe");

			WinRT.Interop.InitializeWithWindow.Initialize(loadPicker, MainWindow.GetWindowHandle());

			StorageFile loadFile = await loadPicker.PickSingleFileAsync();

			if (loadFile == null)
				return;

			PeViewerPathSetting = loadFile.Path;
		}

		private void FontBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			string selectedFont = FontBox.SelectedItem as string;
			if (string.IsNullOrEmpty(selectedFont))
				return;

			if(Settings.Default.Font != selectedFont)
				Settings.Default.Font = selectedFont;
		}

		void OnPropertyChanged([CallerMemberName] string propertyName = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		bool BinaryCacheOptionValueSetting { get => Settings.Default.BinaryCacheOptionValue; set { if (value != Settings.Default.BinaryCacheOptionValue) { Settings.Default.BinaryCacheOptionValue = value; OnPropertyChanged(); FindName(nameof(UpdateNote)); } } }

		string PeViewerPathSetting { get => Settings.Default.PeViewerPath; set { if (value != Settings.Default.PeViewerPath) { Settings.Default.PeViewerPath = value; OnPropertyChanged(); } } }

		string TreeBuildBehaviourSetting { get => Settings.Default.TreeBuildBehaviour; set { if (value != Settings.Default.TreeBuildBehaviour) { Settings.Default.TreeBuildBehaviour = value; OnPropertyChanged(); } } }

		int TreeDepthSetting { get => Settings.Default.TreeDepth; set { if (value != Settings.Default.TreeDepth) { Settings.Default.TreeDepth = value; OnPropertyChanged(); } } }

		ObservableCollection<string> Fonts = new();
		Toolkit.Uwp.UI.AdvancedCollectionView SortedFonts;


		public event PropertyChangedEventHandler PropertyChanged;
	}
}
