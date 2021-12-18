using CommunityToolkit.WinUI.UI.Controls;
using Dependencies.ClrPh;
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
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.ApplicationModel.DataTransfer;
using Windows.Foundation;
using Windows.Foundation.Collections;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Dependencies
{
	public sealed partial class DependencyExportList : DataGridSort
	{
		public DependencyExportList()
		{
			SortedItems = new Toolkit.Uwp.UI.AdvancedCollectionView(Items, true);

			this.InitializeComponent();
			this.RowStyle = DataGridRowStyleWithContextMenu;
		}

		public void SetExports(List<PeExport> Exports, PhSymbolProvider SymPrv)
		{
			using (SortedItems.DeferRefresh())
			{
				this.Items.Clear();

				foreach (PeExport Export in Exports)
				{
					this.Items.Add(new DisplayPeExport(Export, SymPrv));
				}
			}
		}

		private void ExportListCopySelectedValues(XamlUICommand sender, ExecuteRequestedEventArgs args)
		{
			if (this.SelectedItems.Count == 0)
				return;

			List<DisplayPeExport> selectedExports = new List<DisplayPeExport>();
			foreach (var import in this.SelectedItems)
			{
				selectedExports.Add((import as DisplayPeExport));
			}

			string SelectedValues = String.Join("\n", selectedExports.Select(exp => exp.ToString()));

			DataPackage dataPackage = new DataPackage();
			dataPackage.RequestedOperation = DataPackageOperation.Copy;
			dataPackage.SetText(SelectedValues);

			// sometimes another process has "opened" the clipboard, so we need to wait for it
			try
			{
				Clipboard.SetContent(dataPackage);
				Clipboard.Flush();
				return;
			}
			catch { }
		}

		private void ExportListFilter(XamlUICommand sender, ExecuteRequestedEventArgs args)
		{
			OpenFilterWindow();
		}

		private void ItemContextMenu_Opening(object sender, object e)
		{
			// Select item when context menu is opened
			MenuFlyout flyout = sender as MenuFlyout;
			if (flyout != null && flyout.Target is DataGridRow row)
			{
				this.SelectedItem = row.DataContext;
			}
		}

		public ObservableCollection<DisplayPeExport> Items = new ObservableCollection<DisplayPeExport>();
	}
}
