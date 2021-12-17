using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.UI.Popups;

namespace Dependencies
{
	// Implementation of MessageBox using WinRT MessageDialog
	public class MessageBox
	{
		public static MessageBoxResult Show(string text, string caption = "", MessageBoxButton button = MessageBoxButton.OK)
		{
			MainWindow.GetWindow().DispatcherQueue.TryEnqueue(() =>
			{
				MessageDialog dialog = new MessageDialog(text, caption);

				dialog.Commands.Add(new UICommand("Ok"));
				WinRT.Interop.InitializeWithWindow.Initialize(dialog, MainWindow.GetWindowHandle());
				dialog.ShowAsync().AsTask().Wait();
			});
			return MessageBoxResult.OK;

		}
	}

	public enum MessageBoxButton
	{
		OK
	}

	public enum MessageBoxResult
	{
		OK
	}
}
