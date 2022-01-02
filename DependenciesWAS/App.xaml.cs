using CommunityToolkit.WinUI.UI;
using Dependencies;
using Dependencies.ClrPh;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Activation;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Storage;
using Windows.Storage.FileProperties;
using Windows.UI.StartScreen;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Dependencies
{
	/// <summary>
	/// Provides application-specific behavior to supplement the default Application class.
	/// </summary>
	public partial class App : Application, INotifyPropertyChanged
	{
		/// <summary>
		/// Initializes the singleton application object.  This is the first line of authored code
		/// executed, and as such is the logical equivalent of main() or WinMain().
		/// </summary>
		public App()
		{
			this.InitializeComponent();
			iconCache = new Dictionary<string, BitmapImage>();
			thumbnailCache = new InMemoryStorage<BitmapImage>();
			thumbnailCache.MaxItemCount = 1000;
			(Application.Current as App).PropertyChanged += App_PropertyChanged;
		}

		public string StatusBarMessage
		{
			get { return statusBarMessage; }
			set
			{
				if (statusBarMessage != value)
				{
					statusBarMessage = value;
					OnPropertyChanged("StatusBarMessage");
				}
			}
		}

		public event PropertyChangedEventHandler PropertyChanged;
		protected void OnPropertyChanged(string propertyName)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		private void App_PropertyChanged(object sender, PropertyChangedEventArgs e)
		{
			if (e.PropertyName == "StatusBarMessage" && mainWindow != null)
			{
				mainWindow.SetStatusBarMessage(StatusBarMessage);
			}
		}
		public PE LoadBinary(string path)
		{
			StatusBarMessage = String.Format("Loading module {0:s} ...", path);

			if (!NativeFile.Exists(path))
			{
				StatusBarMessage = String.Format("Loading PE file \"{0:s}\" failed : file not present on disk.", path);
				return null;
			}

			PE pe = BinaryCache.LoadPe(path);
			if (pe == null || !pe.LoadSuccessful)
			{
				StatusBarMessage = String.Format("Loading module {0:s} failed.", path);
			}
			else
			{
				StatusBarMessage = String.Format("Loading PE file \"{0:s}\" successful.", pe.Filepath);
			}

			return pe;
		}

		public BitmapImage GetCachedIcon(string path)
		{
			string iconPath = "ms-appx:///" + path;


			if (iconCache.ContainsKey(iconPath))
				return (iconCache[iconPath]);

			BitmapImage newImage = new BitmapImage(new Uri(iconPath));
			iconCache[iconPath] = newImage;
			return newImage;
		}

		public BitmapImage GetCachedThumbnail(string path)
		{
            InMemoryStorageItem<BitmapImage> cachedItem = thumbnailCache.GetItem(path, TimeSpan.FromMinutes(10));
			if (cachedItem != null)
			{
				return cachedItem.Item;
            }
			BitmapImage bitmapImage = new BitmapImage();

            try
            {
				StorageFile file = StorageFile.GetFileFromPathAsync(Path.GetFullPath(path)).AsTask<StorageFile>().Result;

				StorageItemThumbnail thumbnail = file.GetThumbnailAsync(Windows.Storage.FileProperties.ThumbnailMode.SingleItem, 32).AsTask<StorageItemThumbnail>().Result;
				if (thumbnail != null)
				{
					bitmapImage.SetSource(thumbnail);
					thumbnailCache.SetItem(new InMemoryStorageItem<BitmapImage>(path, DateTime.Now, bitmapImage));
					return bitmapImage;
				}
			}
			catch(Exception)
            {
            }

			return GetCachedIcon("Images/Question.png");
		}

		/// <summary>
		/// Invoked when the application is launched normally by the end user.  Other entry points
		/// will be used such as when the application is launched to open a specific file.
		/// </summary>
		/// <param name="args">Details about the launch request and process.</param>
		protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
		{

			Phlib.InitializePhLib();

			// Load singleton for binary caching
			BinaryCache.InitializeBinaryCache(Dependencies.BinaryCacheOption.GetGlobalBehaviour() == Dependencies.BinaryCacheOption.BinaryCacheOptionValue.Yes);

			mainWindow = new MainWindow();

			switch (Phlib.GetClrPhArch())
			{
				case CLRPH_ARCH.x86:
					mainWindow.SetWindowTitle("Dependencies (x86)");
					break;
				case CLRPH_ARCH.x64:
					mainWindow.SetWindowTitle("Dependencies (x64)");
					break;
				case CLRPH_ARCH.ARM64:
					mainWindow.SetWindowTitle("Dependencies (ARM64)");
					break;
				case CLRPH_ARCH.WOW64:
					mainWindow.SetWindowTitle("Dependencies (WoW64)");
					break;
			}

			mainWindow.Activate();
		}

		public void AppExit()
		{
			Dependencies.Properties.Settings.Default.Save();
			BinaryCache.Instance.Unload();
		}

		public static async Task AddToRecentDocuments(String Filename)
		{
			// Store a copy in application settings, LRU style
			// First check if the item is not already present in the list
			int index = Dependencies.Properties.Settings.Default.RecentFiles.IndexOf(Filename);
			if (index != -1)
			{
				Dependencies.Properties.Settings.Default.RecentFiles.RemoveAt(index);
			}

			// Second check if the list is not full
			if (Dependencies.Properties.Settings.Default.RecentFiles.Count == 10)
			{
				Dependencies.Properties.Settings.Default.RecentFiles.RemoveAt(9);
			}

			// Prepend the list with the new item
			Dependencies.Properties.Settings.Default.RecentFiles.Insert(0, Filename);

			// Refresh jumplist.
			JumpList jumpList = await JumpList.LoadCurrentAsync();
			jumpList.SystemGroupKind = Windows.UI.StartScreen.JumpListSystemGroupKind.None;
			jumpList.Items.Clear();
			foreach (string file in Dependencies.Properties.Settings.Default.RecentFiles)
			{
				if(!string.IsNullOrEmpty(file))
					jumpList.Items.Add(JumpListItem.CreateWithArguments(file, Path.GetFileName(file)));
			}
			await jumpList.SaveAsync();
		}

		private MainWindow mainWindow;
		private string statusBarMessage = "";
		private Dictionary<string, BitmapImage> iconCache;
		private InMemoryStorage<BitmapImage> thumbnailCache;
	}
}
