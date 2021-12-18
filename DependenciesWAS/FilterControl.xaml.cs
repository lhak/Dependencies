using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Dependencies
{
	public sealed partial class FilterControl : UserControl, INotifyPropertyChanged
	{
		public FilterControl()
		{
			this.InitializeComponent();
			this.Translation = new System.Numerics.Vector3(0, 0, 16);
		}

		void FilterControl_Loaded(object sender, RoutedEventArgs e)
		{
			FilterText.Focus(FocusState.Programmatic);
		}

		void OnPropertyChanged([CallerMemberName] string propertyName = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}


		public event EventHandler<string> FilterTextChanged;

		public event PropertyChangedEventHandler PropertyChanged;
		public string Filter { get { return _filter; } set { _filter = value; OnPropertyChanged(); } }

		string _filter;

		private void FilterText_TextChanged(object sender, TextChangedEventArgs e)
		{
			FilterTextChanged(this, FilterText.Text);
		}
	}
}
