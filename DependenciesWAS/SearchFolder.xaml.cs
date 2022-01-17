using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
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
	public class SearchFolderItem : INotifyPropertyChanged
	{
		public event PropertyChangedEventHandler PropertyChanged;

		void OnPropertyChanged([CallerMemberName] string propertyName = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		public string Folder
		{
			get { return folder; }
			set { folder = value; OnPropertyChanged(); }
		}

		private string folder;
	}

	/// <summary>
	/// An empty page that can be used on its own or navigated to within a Frame.
	/// </summary>
	public sealed partial class SearchFolder : Page, INotifyPropertyChanged
	{
		public SearchFolder(DependencyWindow SelectedItem)
		{
			_SelectedItem = SelectedItem;
			_working_directory = SelectedItem.WorkingDirectory; // TODO: Set to SelectedItem.RootDirectory in WPF version, but this seems wrong
			_CustomSearchFolders = new ObservableCollection<SearchFolderItem>();
			foreach (var item in SelectedItem.CustomSearchFolders)
			{
				_CustomSearchFolders.Add(
					new SearchFolderItem()
					{
						Folder = item
					}
				);
			}

			/*_CustomSearchFolders.Add(
					new SearchFolderItem()
					{
						Folder = "Test folder"
					}
				);
			_CustomSearchFolders.Add(
					new SearchFolderItem()
					{
						Folder = "Test folder 2"
					}
				);*/
			this.InitializeComponent();
		}

		public void Save()
		{
			List<string> foldersList = _CustomSearchFolders.Select(i => i.Folder).ToList();

			// do not launch analysis again if there is no modifications
			bool searchFoldersChanged = (!_SelectedItem.CustomSearchFolders.SequenceEqual(foldersList) || (WorkingDirectory != _SelectedItem.WorkingDirectory));

			if (searchFoldersChanged)
			{
				_SelectedItem.CustomSearchFolders = foldersList;
				_SelectedItem.WorkingDirectory = WorkingDirectory;

				// Force refresh
				_SelectedItem.InitializeView();
			}
		}

		private void AddFolder(string folderPath)
		{
			// Do not add folder twice
			foreach (SearchFolderItem item in _CustomSearchFolders)
			{
				if (item.Folder == folderPath)
					return;
			}

			_CustomSearchFolders.Add(new SearchFolderItem() { Folder = folderPath });
		}

		public event PropertyChangedEventHandler PropertyChanged;
		void OnPropertyChanged([CallerMemberName] string propertyName = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		private async void SearchFolderList_DragEnter(object sender, DragEventArgs e)
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
				// Check that at least one folder is included
				IReadOnlyList<IStorageItem> items = await e.DataView.GetStorageItemsAsync();
				foreach (IStorageItem item in items)
				{
					if (item.IsOfType(StorageItemTypes.Folder))
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

		private async void SearchFolderList_Drop(object sender, DragEventArgs e)
		{
			e.AcceptedOperation = DataPackageOperation.Copy;
			DragOperationDeferral deferal = e.GetDeferral();
			e.Handled = true;
			try
			{
				IReadOnlyList<IStorageItem> items = await e.DataView.GetStorageItemsAsync();
				foreach (IStorageItem item in items)
				{
					if (item.IsOfType(StorageItemTypes.Folder))
					{
						AddFolder(item.Path);
					}
				}
			}
			catch (Exception)
			{
			}
			deferal.Complete();
		}

		private void RemoveCommand_ExecuteRequested(XamlUICommand sender, ExecuteRequestedEventArgs args)
		{
			for (int i = SearchFolderList.SelectedItems.Count - 1; i >= 0; i--)
			{
				_CustomSearchFolders.RemoveAt(i);
			}
		}

		private async void AddCommand_ExecuteRequested(XamlUICommand sender, ExecuteRequestedEventArgs args)
		{
			FolderPicker folderPicker = new FolderPicker();

			folderPicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;

			WinRT.Interop.InitializeWithWindow.Initialize(folderPicker, MainWindow.GetWindowHandle());

			StorageFolder folder = await folderPicker.PickSingleFolderAsync();

			if (folder == null)
				return;

			AddFolder(folder.Path);
		}

		public ObservableCollection<SearchFolderItem> SearchFolders => _CustomSearchFolders;
		public string WorkingDirectory
		{
			get { return _working_directory; }
			set { _working_directory = value; OnPropertyChanged(); }
		}

		public bool IsEmptyTextVisible(int count) => count == 0;
		public bool IsItemSelected(int index) => index >= 0;
		private DependencyWindow _SelectedItem;
		private string _working_directory;
		private ObservableCollection<SearchFolderItem> _CustomSearchFolders;
	}
}
