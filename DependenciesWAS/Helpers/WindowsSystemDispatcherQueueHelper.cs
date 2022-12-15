using System;
using System.Runtime.InteropServices;

namespace Dependencies.Helpers
{
	internal class WindowsSystemDispatcherQueueHelper
	{
		[StructLayout(LayoutKind.Sequential)]
		struct DispatcherQueueOptions
		{
			internal int dwSize;
			internal int threadType;
			internal int apartmentType;
		}

		[DllImport("CoreMessaging.dll")]
		private static extern int CreateDispatcherQueueController([In] DispatcherQueueOptions options, [In, Out] ref IntPtr dispatcherQueueController);

		IntPtr m_dispatcherQueueController;
		public void EnsureWindowsSystemDispatcherQueueController()
		{
			if (Windows.System.DispatcherQueue.GetForCurrentThread() != null)
			{
				// one already exists, so we'll just use it.
				return;
			}

			if (m_dispatcherQueueController == IntPtr.Zero)
			{
				DispatcherQueueOptions options;
				options.dwSize = Marshal.SizeOf(typeof(DispatcherQueueOptions));
				options.threadType = 2;    // DQTYPE_THREAD_CURRENT
				options.apartmentType = 2; // DQTAT_COM_STA

				CreateDispatcherQueueController(options, ref m_dispatcherQueueController);
			}
		}
	}
}
