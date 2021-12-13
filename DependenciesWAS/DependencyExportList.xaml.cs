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
	public sealed partial class DependencyExportList : DataGridSort
	{
		public DependencyExportList()
		{
			SortedItems = new Toolkit.Uwp.UI.AdvancedCollectionView(Items, true);

			this.InitializeComponent();
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


		public ObservableCollection<DisplayPeExport> Items = new ObservableCollection<DisplayPeExport>();
	}


}
