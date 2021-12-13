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


		public ObservableCollection<DisplayPeImport> Items = new ObservableCollection<DisplayPeImport>();

	}
}
