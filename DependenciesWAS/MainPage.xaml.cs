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
			DependencyWindow newDependencyWindow = new DependencyWindow(Filename);
			newDependencyWindow.Header = Path.GetFileNameWithoutExtension(Filename);
			newDependencyWindow.Tag = Filename;
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
			RecentItemsFlyout.Items.Clear();

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
			if (RecentItemsFlyout.Items.Count == 0)
			{
				MenuFlyoutItem dummyItem = new MenuFlyoutItem() { Style = RecentMenuItemStyle, Text = "No recent items" };
				RecentItemsFlyout.Items.Add(dummyItem);
			}
		}


		private void AddRecentFilesMenuItem(string Filepath, int index)
		{
			RecentMenuItem item = new RecentMenuItem(Filepath);
			Binding textBinding = new Binding();
			textBinding.Source = item;
			textBinding.Path = new PropertyPath(nameof(item.HeaderTitle));
			textBinding.Mode = BindingMode.OneWay;
			MenuFlyoutItem menuItem = new MenuFlyoutItem() { DataContext = item, Style = RecentMenuItemStyle };
			menuItem.SetBinding(MenuFlyoutItem.TextProperty, textBinding);
			menuItem.Click += RecentItem_Click;
			RecentItemsFlyout.Items.Add(menuItem);
		}

		private async void OpenItem_Click(SplitButton sender, SplitButtonClickEventArgs e)
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
			this.CustomizeSearchFoldersItem.IsEnabled = FileTabs.TabItems.Count > 0;
		}

		private async void RootGrid_DragEnter(object sender, DragEventArgs e)
		{
			e.AcceptedOperation = DataPackageOperation.None;

			// Check if the drag contains storage items
			if (e.DataView == null)
				return;

			if (!e.DataView.Contains(StandardDataFormats.StorageItems) && !e.DataView.Contains(StandardDataFormats.ApplicationLink))
				return;

			if (e.DataView.Properties.ContainsKey("windowHandle"))
			{
				// Make sure not to accept drops from the same window
				Int64 handle = (Int64)e.DataView.Properties["windowHandle"];
				if ((Int64)MainWindow.GetWindowHandle() == handle)
					return;
			}

			// Get deferal
			DragOperationDeferral deferal = e.GetDeferral();

			try
			{
				// Check that at least one file is included
				if (e.DataView.Contains(StandardDataFormats.StorageItems))
				{
					IReadOnlyList<IStorageItem> files = await e.DataView.GetStorageItemsAsync();
					foreach (IStorageItem item in files)
					{
						if (item.IsOfType(StorageItemTypes.File))
						{
							e.AcceptedOperation = DataPackageOperation.Copy;
							break;
						}
					}
				}
				else
				{
					Uri file = await e.DataView.GetApplicationLinkAsync();
					if(file.IsFile)
						e.AcceptedOperation = DataPackageOperation.Move;
				}
				// Complete operation
				e.Handled = true;
			}
			catch (Exception)
			{
			}
			deferal.Complete();
		}

		private async void RootGridOrFileTabs_Drop(object sender, DragEventArgs e)
		{
			DragOperationDeferral deferal = e.GetDeferral();
			e.Handled = true;
			try
			{
				if (e.DataView.Contains(StandardDataFormats.StorageItems))
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
				else
				{
					Uri file = await e.DataView.GetApplicationLinkAsync();
					OpenNewDependencyWindow(file.AbsolutePath);
				}
				// Complete operation
				e.Handled = true;
			}
			catch (Exception)
			{
			}
			deferal.Complete();
		}

		private void FileTabs_TabStripDragOver(object sender, DragEventArgs e)
		{
			e.AcceptedOperation = DataPackageOperation.None;

			if (e.DataView.Contains(StandardDataFormats.ApplicationLink))
			{
				e.Handled = true;
				e.AcceptedOperation = DataPackageOperation.Move;
			}
		}

		private void FileTabs_TabDragStarting(TabView sender, TabViewTabDragStartingEventArgs args)
		{
			try
			{
				DependencyWindow window = args.Tab as DependencyWindow;
				args.Data.SetApplicationLink(new Uri(window.Tag.ToString(), UriKind.Absolute));
				args.Data.RequestedOperation = DataPackageOperation.Move;
				args.Data.Properties.ApplicationName = "Dependencies";
				args.Data.Properties.Add("windowHandle", (Int64)MainWindow.GetWindowHandle());
			}
			catch (Exception)
			{

			}
		}

		private void FileTabs_TabDragCompleted(TabView sender, TabViewTabDragCompletedEventArgs args)
		{
			// There does not currently seem to be a way to detect if the drop target is the same window or 
			// tabs are reordered in the same window
			return;
			/*
			if (args.DropResult != DataPackageOperation.Move)
				return;

			// Remove tab if dragged to another window
			FileTabs.TabItems.Remove(args.Tab);*/
		}

		public string VersionStr { get => Assembly.GetEntryAssembly().GetName().Version.ToString(); }

		bool FullPathSetting { get => Settings.Default.FullPath; set { Settings.Default.FullPath = value; OnPropertyChanged(); } }
		bool UndecorateSetting { get => Settings.Default.Undecorate; set { Settings.Default.Undecorate = value; OnPropertyChanged(); } }
		bool ShowStatusBarSetting { get => Settings.Default.ShowStatusBar; set { Settings.Default.ShowStatusBar = value; OnPropertyChanged(); } }

		ObservableCollection<RecentMenuItem> _recentsItems = new ObservableCollection<RecentMenuItem>();
	}
}
