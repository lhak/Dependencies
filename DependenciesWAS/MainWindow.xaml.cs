using Dependencies.Helpers;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using System;
using WinRT;

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

			WindowId myWndId = Win32Interop.GetWindowIdFromWindow(MainWindow.GetWindowHandle());

			AppWindow appWindow = AppWindow.GetFromWindowId(myWndId);

			if (AppWindowTitleBar.IsCustomizationSupported()) // Check for Windows 11
			{
				appWindow.TitleBar.ExtendsContentIntoTitleBar = true;
				appWindow.TitleBar.ButtonBackgroundColor = Colors.Transparent;
				appWindow.TitleBar.ButtonInactiveBackgroundColor = Colors.Transparent;
			}
			else
			{
				this.ExtendsContentIntoTitleBar = true;
				SetTitleBar(TitleBar);
			}
			appWindow.SetIcon("Dependencies.ico");

			TrySetMicaBackdrop();
		}

		private void Window_Closed(object sender, WindowEventArgs args)
		{
			(App.Current as App).AppExit();

			// Make sure any Mica/Acrylic controller is disposed so it doesn't try to
			// use this closed window.
			if (_micaController != null)
			{
				_micaController.Dispose();
				_micaController = null;
			}
		}

		private void Window_Activated(object sender, WindowActivatedEventArgs args)
		{
			if(_micaController != null)
				_configurationSource.IsInputActive = args.WindowActivationState != WindowActivationState.Deactivated;
		}

		private void RootGrid_ActualThemeChanged(FrameworkElement sender, object args)
		{
			UpdateMicaTheme();
		}

		public static MainWindow GetWindow()
		{
			return _mainWindow;
		}

		public static IntPtr GetWindowHandle()
		{
			return _windowHandle;
		}

		public void SetStatusBarMessage(string message)
		{
			RootPage.SetStatusBarMessage(message);
		}

		public void SetWindowTitle(string title)
		{
			this.Title = title;
			TitleBarText.Text = title;
		}

		public void OpenNewTab(string filepath)
		{
			RootPage.OpenNewDependencyWindow(filepath);
		}

		bool TrySetMicaBackdrop()
		{
			if (Microsoft.UI.Composition.SystemBackdrops.MicaController.IsSupported())
			{
				RootGrid.Background = null;

				_wsdqHelper = new WindowsSystemDispatcherQueueHelper();
				_wsdqHelper.EnsureWindowsSystemDispatcherQueueController();

				// Hooking up the policy object
				_configurationSource = new Microsoft.UI.Composition.SystemBackdrops.SystemBackdropConfiguration();

				// Initial configuration state.
				_configurationSource.IsInputActive = true;

				_micaController = new Microsoft.UI.Composition.SystemBackdrops.MicaController();

				UpdateMicaTheme();

				// Enable the system backdrop.
				// Note: Be sure to have "using WinRT;" to support the Window.As<...>() call.
				_micaController.AddSystemBackdropTarget(this.As<Microsoft.UI.Composition.ICompositionSupportsSystemBackdrop>());
				_micaController.SetSystemBackdropConfiguration(_configurationSource);
				return true; // succeeded
			}
			return false; // Mica is not supported on this system
		}


		private void UpdateMicaTheme()
		{
			if (_micaController != null)
			{
				switch (((FrameworkElement)this.Content).ActualTheme)
				{
					case ElementTheme.Dark: _configurationSource.Theme = Microsoft.UI.Composition.SystemBackdrops.SystemBackdropTheme.Dark; break;
					case ElementTheme.Light: _configurationSource.Theme = Microsoft.UI.Composition.SystemBackdrops.SystemBackdropTheme.Light; break;
					case ElementTheme.Default: _configurationSource.Theme = Microsoft.UI.Composition.SystemBackdrops.SystemBackdropTheme.Default; break;
				}
			}
		}

		private static MainWindow _mainWindow;
		private static IntPtr _windowHandle;
		WindowsSystemDispatcherQueueHelper _wsdqHelper; // See separate sample below for implementation
		Microsoft.UI.Composition.SystemBackdrops.MicaController _micaController;
		Microsoft.UI.Composition.SystemBackdrops.SystemBackdropConfiguration _configurationSource;
	}
}
