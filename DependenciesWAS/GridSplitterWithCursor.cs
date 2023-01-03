using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.UI.Core;

namespace Dependencies
{
    // The Toolkit GridSplitter currently does not currently support cursor changes on WinUI3
    // Add a simple implementation of it here

    class GridSplitterWithCursor : GridSplitter
    {
        public GridSplitterWithCursor()
        {
            this.Loaded += GridSplitterWithCursor_Loaded;
            this.Unloaded += GridSplitterWithCursor_Unloaded;

            _gridSplitterDirection = GetResizeDirection();

        }

        private GridResizeDirection _gridSplitterDirection;
        private InputCursor _previousCursor;
        private bool _isDragging;

        private void GridSplitterWithCursor_PointerEntered(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
        {
            // if not dragging
            if (!_isDragging)
            {
                _previousCursor = this.ProtectedCursor;
                UpdateDisplayCursor();
            }
        }

        private void GridSplitterWithCursor_PointerExited(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
        {
            if (!_isDragging)
            {
                this.ProtectedCursor = _previousCursor;
            }
        }
      
        private void GridSplitterWithCursor_Unloaded(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {
            // Somehow called after the Loaded event. Check if parent element is set.
            if (this.Parent == null)
            {
                UnhookEvents();
            }
        }

        private void GridSplitterWithCursor_Loaded(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {
            _gridSplitterDirection = GetResizeDirection();

            HookEvents();
        }

        void UnhookEvents()
        {
            PointerEntered -= GridSplitterWithCursor_PointerEntered;
            PointerExited -= GridSplitterWithCursor_PointerExited;
            PointerPressed -= GridSplitterWithCursor_PointerPressed;
            PointerCaptureLost -= GridSplitterWithCursor_PointerCaptureLost;
        }

        void HookEvents()
        {
            UnhookEvents();
            PointerEntered += GridSplitterWithCursor_PointerEntered;
            PointerExited += GridSplitterWithCursor_PointerExited;
            PointerPressed += GridSplitterWithCursor_PointerPressed;
            PointerCaptureLost += GridSplitterWithCursor_PointerCaptureLost;
        }

        private void GridSplitterWithCursor_PointerCaptureLost(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
        {
            this.ReleasePointerCapture(e.Pointer);
            _isDragging = false;
        }

        private void GridSplitterWithCursor_PointerPressed(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
        {
            this.CapturePointer(e.Pointer);
            _isDragging = true;
        }

        private void UpdateDisplayCursor()
        {
            if (_gridSplitterDirection == GridSplitter.GridResizeDirection.Columns)
            {
                this.ProtectedCursor = InputSystemCursor.Create(InputSystemCursorShape.SizeWestEast);
            }
            else if (_gridSplitterDirection == GridSplitter.GridResizeDirection.Rows)
            {
                this.ProtectedCursor = InputSystemCursor.Create(InputSystemCursorShape.SizeNorthSouth);
            }
        }

        // Checks the control alignment and Width/Height to detect the control resize direction columns/rows
        private GridResizeDirection GetResizeDirection()
        {
            GridResizeDirection direction = ResizeDirection;

            if (direction == GridResizeDirection.Auto)
            {
                // When HorizontalAlignment is Left, Right or Center, resize Columns
                if (HorizontalAlignment != HorizontalAlignment.Stretch)
                {
                    direction = GridResizeDirection.Columns;
                }

                // When VerticalAlignment is Top, Bottom or Center, resize Rows
                else if (VerticalAlignment != VerticalAlignment.Stretch)
                {
                    direction = GridResizeDirection.Rows;
                }

                // Check Width vs Height
                else if (ActualWidth <= ActualHeight)
                {
                    direction = GridResizeDirection.Columns;
                }
                else
                {
                    direction = GridResizeDirection.Rows;
                }
            }

            return direction;
        }
    }
}
