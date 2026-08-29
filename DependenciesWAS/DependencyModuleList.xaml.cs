using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using System.Collections.Generic;
using System.Collections.ObjectModel;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Dependencies
{
	public class ModuleCacheKey
	{
		public ModuleCacheKey(string _Name, string _Filepath, ModuleFlag _Flags = ModuleFlag.NoFlag)
		{
			Name = _Name;
			Filepath = _Filepath;
			Flags = _Flags;
		}

		public ModuleCacheKey(ImportContext import)
		{
			Name = import.ModuleName;
			Filepath = import.PeFilePath;
			Flags = import.Flags;
		}

		// mandatory since ModuleCacheKey is used as a dictionnary key
		public override int GetHashCode()
		{
			int hashcode = Name.GetHashCode() ^ Flags.GetHashCode();

			if (Filepath != null)
			{
				hashcode ^= Filepath.GetHashCode();
			}

			return hashcode;
		}

        public override bool Equals(object obj)
        {
			if (obj is not ModuleCacheKey otherKey)
				return false;

			return Name == otherKey.Name && Flags == otherKey.Flags && Filepath == otherKey.Filepath;
        }

		public string Name;
		public string Filepath;
		public ModuleFlag Flags;
	}

	public partial class ModulesCache : Dictionary<ModuleCacheKey, DisplayModuleInfo>
	{

	}

	public sealed partial class DependencyModuleList : DataGridSort
	{
		public RelayCommand DoFindModuleInTreeCommand
		{
			get { return (RelayCommand)GetValue(DoFindModuleInTreeCommandProperty); }
			set { SetValue(DoFindModuleInTreeCommandProperty, value); }
		}

		public RelayCommand ShowAllDependenciesCommand
        {
			get { return (RelayCommand)GetValue(ShowAllDependenciesCommandProperty); }
			set { SetValue(ShowAllDependenciesCommandProperty, value); }
		}

		public event RoutedEventHandler SelectedModuleChanged;

		// Using a DependencyProperty as the backing store for DoFindModuleInTreeCommand.  This enables animation, styling, binding, etc...
		public static readonly DependencyProperty DoFindModuleInTreeCommandProperty =
			DependencyProperty.Register("DoFindModuleInTreeCommand", typeof(RelayCommand), typeof(DependencyModuleList), new PropertyMetadata(null));

		public static readonly DependencyProperty ShowAllDependenciesCommandProperty =
			DependencyProperty.Register("ShowAllDependenciesCommand", typeof(RelayCommand), typeof(DependencyModuleList), new PropertyMetadata(null));

		public DependencyModuleList()
		{
			SortedItems = new CommunityToolkit.WinUI.Collections.AdvancedCollectionView(Items, true);
			this.InitializeComponent();
			this.RowStyle = DataGridRowStyleWithContextMenu;
		}

		public void AddModule(DisplayModuleInfo NewModule)
		{
			// TODO : Find a way to properly bind commands instead of using this hack
			NewModule.DoFindModuleInTreeCommand = DoFindModuleInTreeCommand;
			NewModule.ShowAllDependenciesCommand = ShowAllDependenciesCommand;

			Items.Add(NewModule);
		}

		private void ModuleListFilter(XamlUICommand sender, ExecuteRequestedEventArgs args)
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

        private void DataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			SelectedModuleChanged.Invoke(this, e);
		}

		public ObservableCollection<DisplayModuleInfo> Items = new ObservableCollection<DisplayModuleInfo>();
    }
}
