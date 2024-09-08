using System.ComponentModel;
using System.Collections.Generic;
using CommunityToolkit.WinUI.Helpers;

namespace Dependencies
{
    public partial class SettingBindingHandler : INotifyPropertyChanged
    {
        public delegate string CallbackEventHandler(bool settingValue);
        public struct EventHandlerInfo
        {
            public string Property;
            public string Settings;
            public string MemberBindingName;
            public CallbackEventHandler Handler;
        }

        public event PropertyChangedEventHandler PropertyChanged;
        private List<EventHandlerInfo> Handlers;

        public SettingBindingHandler()
        {
			// Use weak event listener here to avoid memory leaks
			WeakEventListener<SettingBindingHandler, object, PropertyChangedEventArgs> propertyChangedWeakEventListener =
                       new WeakEventListener<SettingBindingHandler, object, PropertyChangedEventArgs>(this)
                       {
                            // Call the actual collection changed event
                            OnEventAction = (source, changed, arg3) => source.Handler_PropertyChanged(source, arg3),

                            // The source doesn't exist anymore
                            OnDetachAction = (listener) => Dependencies.Properties.Settings.Default.PropertyChanged -= listener.OnEvent
                       };

            Dependencies.Properties.Settings.Default.PropertyChanged += propertyChangedWeakEventListener.OnEvent;
            Handlers = new List<EventHandlerInfo>();
        }

        public void AddNewEventHandler(string PropertyName, string SettingsName, string MemberBindingName, CallbackEventHandler Handler)
        {
            EventHandlerInfo info = new EventHandlerInfo();
            info.Property = PropertyName;
            info.Settings = SettingsName;
            info.MemberBindingName = MemberBindingName;
            info.Handler = Handler;

            Handlers.Add(info);
        }

        public virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private void Handler_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            foreach (EventHandlerInfo Handler in Handlers.FindAll(x => x.Property == e.PropertyName))
            {
                Handler.Handler(((bool)Dependencies.Properties.Settings.Default[Handler.Settings]));
                OnPropertyChanged(Handler.MemberBindingName);
            }
        }
    }
}
