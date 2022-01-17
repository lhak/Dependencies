using Dependencies.Properties;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.ApplicationModel.DataTransfer;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Storage;
using Windows.Storage.Pickers;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Dependencies
{

	public class RecentMenuItem : SettingBindingHandler
	{
		public RecentMenuItem(string _Filepath)
		{
			Filepath = _Filepath;

			GetHeaderTitle(Properties.Settings.Default.FullPath);

			AddNewEventHandler("FullPath", "FullPath", "HeaderTitle", GetHeaderTitle);

		}

		~RecentMenuItem()
		{

		}

		string GetHeaderTitle(bool FullPath)
		{
			if (Properties.Settings.Default.FullPath)
				HeaderTitle = Filepath;
			else
				HeaderTitle = System.IO.Path.GetFileName(Filepath);

			return HeaderTitle;
		}

		public string Filepath { get; set; }

		public string HeaderTitle { get; set; }
	}

	/// <summary>
	/// An empty page that can be used on its own or navigated to within a Frame.
	/// </summary>
	public sealed partial class MainPage : Page, INotifyPropertyChanged
	{
		public MainPage()
		{
			this.InitializeComponent();

			PopulateRecentFilesMenuItems();

#if DEBUG
			OpenNewDependencyWindow(Path.GetFullPath("coreclr.dll"));
#endif
			// Process command line args
			string[] args = Environment.GetCommandLineArgs();
			if (args.Length > 1)
			{
				OpenNewDependencyWindow(args[1]);
			}
		}

		public event PropertyChangedEventHandler PropertyChanged;

		void OnPropertyChanged([CallerMemberName] string propertyName = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		public void SetStatusBarMessage(string message)
		{
			AppStatusBar.Message = message;
		}

		/// <summary>
		/// Open a new depedency tree window on a given PE.
		/// </summary>
		/// <param name="Filename">File path to a PE to process.</param>
		public async void OpenNewDependencyWindow(String Filename)
		{
			var newDependencyWindow = new DependencyWindow(Filename);
			newDependencyWindow.Header = Path.GetFileNameWithoutExtension(Filename);

			FileTabs.TabItems.Add(newDependencyWindow);
			FileTabs.SelectedItem = newDependencyWindow;

			// Update recent files entries
			await App.AddToRecentDocuments(Filename);
			PopulateRecentFilesMenuItems();
		}

		/// <summary>
		/// Populate "recent entries" menu items
		/// </summary>
		public void PopulateRecentFilesMenuItems()
		{
			// TODO: Find a few to update the recent menu without rebuilding it
			int index = FileMenu.Items.IndexOf(RecentItems);
			FileMenu.Items.Remove(RecentItems);



			RecentItems = new MenuFlyoutSubItem() { Text = "Recent Items" };
			var o = App.Current.Resources["FlyoutThemeMaxWidth"];

			if (Properties.Settings.Default.RecentFiles.Count == 0)
			{
				return;
			}

			foreach (var RecentFilePath in Properties.Settings.Default.RecentFiles)
			{
				// Ignore empty dummy entries
				if (String.IsNullOrEmpty(RecentFilePath))
				{
					continue;
				}

				AddRecentFilesMenuItem(RecentFilePath, Properties.Settings.Default.RecentFiles.IndexOf(RecentFilePath));
			}
			RecentItems.IsEnabled = RecentItems.Items.Count > 0;
			FileMenu.Items.Insert(index, RecentItems);
		}


		private void AddRecentFilesMenuItem(string Filepath, int index)
		{
			RecentItems.Items.Add(new MenuFlyoutItem() { DataContext = new RecentMenuItem(Filepath), Style = RecentMenuItemStyle });
			//_recentsItems.Add(new RecentMenuItem(Filepath));
		}

		private async void OpenItem_Click(object sender, RoutedEventArgs e)
		{
			FileOpenPicker loadPicker = new FileOpenPicker();

			loadPicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
			loadPicker.FileTypeFilter.Add("*");

			WinRT.Interop.InitializeWithWindow.Initialize(loadPicker, MainWindow.GetWindowHandle());

			StorageFile loadFile = await loadPicker.PickSingleFileAsync();

			if (loadFile == null)
				return;

			OpenNewDependencyWindow(loadFile.Path);

		}

		private void RecentItem_Click(object sender, RoutedEventArgs e)
		{
			MenuFlyoutItem RecentFile = sender as MenuFlyoutItem;
			String RecentFilePath = (RecentFile.DataContext as RecentMenuItem).Filepath;

			if (RecentFilePath.Length != 0)
			{
				OpenNewDependencyWindow(RecentFilePath);
			}

			// TODO: Remove this once there is way to bind a list of MenuFlyoutItems
			IExpandCollapseProvider provider = MenuBarItemAutomationPeer.FromElement(FileMenu) as IExpandCollapseProvider;
			provider.Collapse();
		}

		private void ExitItem_Click(object sender, RoutedEventArgs e)
		{
			MainWindow.GetWindow().Close();
		}

		private void RefreshItem_Click(object sender, RoutedEventArgs e)
		{
			DependencyWindow SelectedItem = FileTabs.SelectedItem as DependencyWindow;
			if (SelectedItem == null)
				return;

			SelectedItem.InitializeView();
		}
		private async void CustomizeSearchFolderItem_Click(object sender, RoutedEventArgs e)
		{
			DependencyWindow SelectedItem = FileTabs.SelectedItem as DependencyWindow;
			if (SelectedItem == null)
				return;

			ContentDialog dialog = new ContentDialog()
			{
				Title = "Search folders",
				CloseButtonText = "Cancel",
				PrimaryButtonText = "Ok",
				DefaultButton = ContentDialogButton.Primary,
				Content = new SearchFolder(SelectedItem),
				XamlRoot = this.XamlRoot
			};

			TypedEventHandler<ContentDialog, ContentDialogButtonClickEventArgs> OkHandler = (sender, args) => { (sender.Content as SearchFolder).Save(); };

			dialog.PrimaryButtonClick += OkHandler;
			await dialog.ShowAsync();
			dialog.PrimaryButtonClick -= OkHandler;

		}

		private void Dialog_CloseButtonClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
		{

		}

		private async void UserSettingsItem_Click(object sender, RoutedEventArgs e)
		{
			ContentDialog dialog = new ContentDialog()
			{
				Title = "Properties",
				CloseButtonText = "Close",
				DefaultButton = ContentDialogButton.Close,
				Content = new UserSettings(),
				XamlRoot = this.XamlRoot
			};

			await dialog.ShowAsync();
		}

		private async void AboutItem_Click(object sender, RoutedEventArgs e)
		{
			TextBlock text = new TextBlock();
			text.Inlines.Add(new Span()
			{
				Inlines = {
							new Run() { FontWeight = FontWeights.SemiBold, Text = "Dependencies for WindowsAppSDK v" + VersionStr  },
							new LineBreak(),
							new LineBreak(),
							new Run() { Text = "Port of Dependencies by lucasg (" },
							new Hyperlink() { NavigateUri = new Uri("https://github.com/lucasg/Dependencies"),
								Inlines = { new Run() { Text = "https://github.com/lucasg/Dependencies" } }
							},
							new Run() { Text = ")"}
				}
			});

			ContentDialog dialog = new ContentDialog()
			{
				Title = "About",
				CloseButtonText = "Close",
				DefaultButton = ContentDialogButton.Close,
				Content = text,
				XamlRoot = this.XamlRoot
			};
			await dialog.ShowAsync();
		}

		private void FileTabs_TabCloseRequested(TabView sender, TabViewTabCloseRequestedEventArgs args)
		{
			FileTabs.TabItems.Remove(args.Item);
		}
		private void FileTabs_TabItemsChanged(TabView sender, IVectorChangedEventArgs args)
		{
			this.DefaultMessage.Visibility = FileTabs.TabItems.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
			this.FileTabs.Visibility = FileTabs.TabItems.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
			this.RefreshItem.IsEnabled = FileTabs.TabItems.Count > 0;
		}

		private async void RootGrid_DragEnter(object sender, DragEventArgs e)
		{
			// Check if the drag contains storage items
			if (e.DataView == null)
				return;

			if (!e.DataView.Contains(StandardDataFormats.StorageItems))
				return;

			// Get deferal
			DragOperationDeferral deferal = e.GetDeferral();

			e.AcceptedOperation = DataPackageOperation.None;

			try
			{
				// Check that at least one file is included
				IReadOnlyList<IStorageItem> files = await e.DataView.GetStorageItemsAsync();
				foreach (IStorageItem item in files)
				{
					if (item.IsOfType(StorageItemTypes.File))
					{
						e.AcceptedOperation = DataPackageOperation.Copy;
						break;
					}
				}

				// Complete operation
				e.Handled = true;
			}
			catch (Exception)
			{
			}
			deferal.Complete();
		}

		private async void RootGrid_Drop(object sender, DragEventArgs e)
		{
			e.AcceptedOperation = DataPackageOperation.Copy;
			DragOperationDeferral deferal = e.GetDeferral();
			e.Handled = true;
			try
			{
				IReadOnlyList<IStorageItem> files = await e.DataView.GetStorageItemsAsync();
				foreach (IStorageItem item in files)
				{
					if (item.IsOfType(StorageItemTypes.File))
					{
						deferal.Complete();
						OpenNewDependencyWindow(item.Path);
						return;
					}
				}
			}
			catch (Exception)
			{
			}
			deferal.Complete();
		}

		public string VersionStr { get => Assembly.GetEntryAssembly().GetName().Version.ToString(); }

		bool FullPathSetting { get => Settings.Default.FullPath; set { Settings.Default.FullPath = value; OnPropertyChanged(); } }
		bool UndecorateSetting { get => Settings.Default.Undecorate; set { Settings.Default.Undecorate = value; OnPropertyChanged(); } }
		bool ShowStatusBarSetting { get => Settings.Default.ShowStatusBar; set { Settings.Default.ShowStatusBar = value; OnPropertyChanged(); } }

		ObservableCollection<RecentMenuItem> _recentsItems = new ObservableCollection<RecentMenuItem>();
	}
}
