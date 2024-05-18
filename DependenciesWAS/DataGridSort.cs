using CommunityToolkit.WinUI.Collections;
using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Windows.Foundation;

namespace Dependencies
{
	public class DataGridSort : DataGrid
	{
		public static readonly DependencyProperty SearchListFilterProperty = DependencyProperty.Register(
		 "SearchListFilter", typeof(string), typeof(DataGridSort), new PropertyMetadata(null));

		public string SearchListFilter
		{
			get { return (string)GetValue(SearchListFilterProperty); }
			set { SetValue(SearchListFilterProperty, value); }
		}


		protected void SortDataGrid(object sender, DataGridColumnEventArgs e)
		{
			string category = e.Column.Tag as string;
			if (category == null)
				return;

            SortDirection direction = SortDirection.Descending;

			if (e.Column.SortDirection == null || e.Column.SortDirection == DataGridSortDirection.Descending)
			{
				direction = SortDirection.Ascending;
				e.Column.SortDirection = DataGridSortDirection.Ascending;
			}
			else
			{
				e.Column.SortDirection = DataGridSortDirection.Descending;
			}

			using (SortedItems.DeferRefresh())
			{
				SortedItems.SortDescriptions.Clear();
				SortedItems.SortDescriptions.Add(new SortDescription(category, direction));
			}

			// Remove sorting indicators from other columns
			foreach (var dgColumn in Columns)
			{
				if (dgColumn.Tag != null && dgColumn.Tag.ToString() != category)
				{
					dgColumn.SortDirection = null;
				}
			}
		}

		protected void OpenFilterWindow()
		{
			if(_filterPopup == null)
			{
				_filterPopup = new Popup();
				_filterPopup.Child = new FilterControl();
				_filterPopup.XamlRoot = this.XamlRoot;
				_filterPopup.IsLightDismissEnabled = true;
				
			}
		
			Point pos = this.TransformToVisual(null).TransformPoint(new Point(0, 0));
			_filterPopup.HorizontalOffset = pos.X;
			_filterPopup.VerticalOffset = pos.Y;

			FilterControl filterControl = _filterPopup.Child as FilterControl;

			if (!_filterPopup.IsOpen)
			{
				filterControl.FilterTextChanged += FilterControl_FilterTextChanged1;
				_filterPopup.Closed += FilterPopup_Closed;
				_filterPopup.IsOpen = true;
			}
		}

		private void FilterPopup_Closed(object sender, object e)
		{
			_filterPopup.Closed -= FilterPopup_Closed;
			FilterControl filterControl = _filterPopup.Child as FilterControl;
			filterControl.FilterTextChanged -= FilterControl_FilterTextChanged1;
		}

        [UnconditionalSuppressMessage("", "IL2065:The method has a DynamicallyAccessedMembersAttribute(which applies to the implicit 'this' parameter), but the value used for the 'this' parameter can not be statically analyzed.",
          Justification = "Accessed classes are annotated with [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] attribute")]
        private void FilterControl_FilterTextChanged1(object sender, string e)
		{
			Type elementType = SortedItems.SourceCollection.GetType().GetGenericArguments()[0];
			PropertyInfo property = elementType.GetProperty(SearchListFilter);
			
			using (SortedItems.DeferRefresh())
			{
				SortedItems.Filter = x => (property.GetValue(x) as string).Contains(e, StringComparison.OrdinalIgnoreCase);
			}
		}

		private Popup _filterPopup = null;
		protected CommunityToolkit.WinUI.Collections.AdvancedCollectionView SortedItems;

	}
}
