using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Dependencies
{
	/// <summary>
	/// An empty window that can be used on its own or navigated to within a Frame.
	/// </summary>
	public sealed partial class MainWindow : Window
	{
		public MainWindow()
		{
			_mainWindow = this;

			_windowHandle = WinRT.Interop.WindowNative.GetWindowHandle(this);

			this.InitializeComponent();
		}

		private void Window_Closed(object sender, WindowEventArgs args)
		{
			(App.Current as App).AppExit();
		}

		public static MainWindow GetWindow()
		{
			return _mainWindow;
		}

		public static IntPtr GetWindowHandle()
		{
			return _windowHandle;
		}

		private static MainWindow _mainWindow;
		private static IntPtr _windowHandle;
	}
}
