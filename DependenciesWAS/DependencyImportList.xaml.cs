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
	public sealed partial class DependencyImportList : DataGridSort
	{
		public DependencyImportList()
		{
			SortedItems = new Toolkit.Uwp.UI.AdvancedCollectionView(Items, true);

			this.InitializeComponent();
			this.RowStyle = DataGridRowStyleWithContextMenu;
		}

		public void SetImports(string ModuleFilepath, List<PeExport> Exports, List<PeImportDll> ParentImports, PhSymbolProvider SymPrv, DependencyWindow Dependencies)
		{
			using (SortedItems.DeferRefresh())
			{
				this.Items.Clear();

				foreach (PeImportDll DllImport in ParentImports)
				{
					foreach (var Import in BinaryCache.LookupImports(DllImport, Exports))
					{
						this.Items.Add(new DisplayPeImport(Import.Item1, SymPrv, ModuleFilepath, Import.Item2));
					}
				}
			}
		}

		public void SetRootImports(List<PeImportDll> Imports, PhSymbolProvider SymPrv, DependencyWindow Dependencies)
		{
			using (SortedItems.DeferRefresh())
			{
				this.Items.Clear();

				foreach (PeImportDll DllImport in Imports)
				{

					PE ModuleImport = Dependencies.LoadImport(DllImport.Name, null, DllImport.IsDelayLoad());
					string ModuleFilepath = (ModuleImport != null) ? ModuleImport.Filepath : null;

					foreach (var Import in BinaryCache.LookupImports(DllImport, ModuleFilepath))
					{
						this.Items.Add(new DisplayPeImport(Import.Item1, SymPrv, ModuleFilepath, Import.Item2));
					}
				}
			}
		}
		private void ImportListCopySelectedValues(XamlUICommand sender, ExecuteRequestedEventArgs args)
		{
			if (this.SelectedItems.Count == 0)
				return;

			List<DisplayPeImport> selectedImports = new List<DisplayPeImport>();
			foreach (var import in this.SelectedItems)
			{
				selectedImports.Add((import as DisplayPeImport));
			}

			string SelectedValues = String.Join("\n", selectedImports.Select(imp => imp.ToString()));

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

		private void ImportListFilter(XamlUICommand sender, ExecuteRequestedEventArgs args)
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

		public ObservableCollection<DisplayPeImport> Items = new ObservableCollection<DisplayPeImport>();
	}
}
