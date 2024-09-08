using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
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

			this.ExtendsContentIntoTitleBar = true;
			SetTitleBar(TitleBar);

			appWindow.SetIcon("Assets\\Dependencies.ico");

            this.SystemBackdrop = new MicaBackdrop();
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

		private static MainWindow _mainWindow;
		private static IntPtr _windowHandle;
	}
}
