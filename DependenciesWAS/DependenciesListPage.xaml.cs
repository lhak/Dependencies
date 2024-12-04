using Dependencies.ClrPh;
using Dependencies.Properties;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Windows.ApplicationModel.DataTransfer;
using Windows.ApplicationModel.Store;
using Windows.Foundation;
using Windows.Foundation.Collections;
using WinRT;

namespace Dependencies
{
    [GeneratedBindableCustomProperty]
    public partial class CustomDataGroup
    {
        public CustomDataGroup()
        {
            //this.Items = new ObservableCollection<DisplayModuleInfo>();
            //this.Key = new string("Test");
        }

        public object Key { get; set; }

        public ICollectionView Items { get; set; }
    }

    public sealed partial class DependenciesListPage : Page
    {
        public DependenciesListPage(PE rootModule, List<string> customSearchFolders, SxsEntries sxsEntriesCache, string workingDirectory, string filepath)
        {
            _processedFiles = new();
            _cts = new();
            _items = new();
            _filteredItems = new();
            //_filteredItems = new(_items, true);

            _rootModule = rootModule;
            _customSearchFolders = customSearchFolders;
            _sxsEntriesCache = sxsEntriesCache;
            _workingDirectory = workingDirectory;
            _filePath = filepath;

            this.DataContext = this;

            this.InitializeComponent();

            //groups.Add(new CustomDataGroup() { Key = "Test", Items = new CommunityToolkit.WinUI.Collections.AdvancedCollectionView() });

            //var g = groupViewSource.View.CollectionGroups;

            /*groups.Add(new CustomDataGroup() { Items = _filteredItems });


            CollectionViewSource src = new CollectionViewSource();
            src.ItemsPath = new PropertyPath("Items");
            src.IsSourceGrouped = true;
            src.Source = groups;
            */
            //ItemList.ItemsSource = src;

            UpdateFont();
        }

        PE _rootModule;
        List<string> _customSearchFolders;
        string _workingDirectory;
        SxsEntries _sxsEntriesCache;
        string _filePath;
        Dictionary<string, ModuleFlag> _processedFiles;
        CancellationTokenSource _cts;
        int _runningWorkers = 0;

        Dictionary<ModuleSearchStrategy, ObservableCollection<DisplayModuleInfo>> _items;
        Dictionary<ModuleSearchStrategy, CommunityToolkit.WinUI.Collections.AdvancedCollectionView> _filteredItems;

        ObservableCollection<CustomDataGroup> groups = new ObservableCollection<CustomDataGroup>();

        private void AddItem(DisplayModuleInfo info)
        {
            ObservableCollection<DisplayModuleInfo> itemList;

            if (_items.TryGetValue(info.Location, out itemList) == false)
            {
                itemList = new();
                CommunityToolkit.WinUI.Collections.AdvancedCollectionView filteredList = new(itemList, true);

                _items[info.Location] = itemList;
                _filteredItems[info.Location] = filteredList;

                groups.Add(new CustomDataGroup() { Key = info.Location.ToString(), Items = filteredList });
            }
            itemList.Add(info);
        }

        // Copied from DependencyWindow.cs

        private ImportContext ResolveImport(PeImportDll DllImport)
        {
            ImportContext ImportModule = new ImportContext();

            ImportModule.PeFilePath = null;
            ImportModule.PeProperties = null;
            ImportModule.ModuleName = DllImport.Name;
            ImportModule.ApiSetModuleName = null;
            ImportModule.Flags = 0;
            if (DllImport.IsDelayLoad())
            {
                ImportModule.Flags |= ModuleFlag.DelayLoad;
            }

            Tuple<ModuleSearchStrategy, PE> ResolvedModule = BinaryCache.ResolveModule(
                    this._rootModule,
                    DllImport.Name,
                    this._sxsEntriesCache,
                    this._customSearchFolders,
                    this._workingDirectory
                );

            ImportModule.ModuleLocation = ResolvedModule.Item1;
            if (ImportModule.ModuleLocation != ModuleSearchStrategy.NOT_FOUND)
            {
                ImportModule.PeProperties = ResolvedModule.Item2;

                if (ResolvedModule.Item2 != null)
                {
                    ImportModule.PeFilePath = ResolvedModule.Item2.Filepath;
                    /*foreach (var Import in BinaryCache.LookupImports(DllImport, ImportModule.PeFilePath))
                    {
                        if (!Import.Item2)
                        {
                            ImportModule.Flags |= ModuleFlag.MissingImports;
                            break;
                        }

                    }*/
                }
            }
            else
            {
                ImportModule.Flags |= ModuleFlag.NotFound;
            }

            // special case for apiset schema
            ImportModule.IsApiSet = (ImportModule.ModuleLocation == ModuleSearchStrategy.ApiSetSchema);
            if (ImportModule.IsApiSet)
            {
                ImportModule.Flags |= ModuleFlag.ApiSet;
                ImportModule.ApiSetModuleName = BinaryCache.LookupApiSetLibrary(DllImport.Name);

                if (DllImport.Name.StartsWith("ext-"))
                {
                    ImportModule.Flags |= ModuleFlag.ApiSetExt;
                }
            }

            return ImportModule;
        }

        private void ProcessAppInitDlls(Dictionary<string, ImportContext> NewTreeContexts, PE AnalyzedPe, ImportContext ImportModule)
        {
            List<PeImportDll> PeImports = AnalyzedPe.GetImports();

            // only user32 triggers appinit dlls
            string User32Filepath = Path.Combine(FindPe.GetSystemPath(this._rootModule), "user32.dll");
            if (string.Compare(ImportModule.PeFilePath, User32Filepath, StringComparison.OrdinalIgnoreCase) != 0)
            {
                return;
            }

            string AppInitRegistryKey =
                (this._rootModule.IsArm32Dll()) ?
                "SOFTWARE\\WowAA32Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows" :
                (this._rootModule.IsWow64Dll()) ?
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows" :
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";

            // Opening registry values
            RegistryKey localKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, RegistryView.Registry64);
            localKey = localKey.OpenSubKey(AppInitRegistryKey);
            int LoadAppInitDlls = (int)localKey.GetValue("LoadAppInit_DLLs", 0);
            string AppInitDlls = (string)localKey.GetValue("AppInit_DLLs", "");
            if (LoadAppInitDlls == 0 || String.IsNullOrEmpty(AppInitDlls))
            {
                return;
            }

            // Extremely crude parser. TODO : Add support for quotes wrapped paths with spaces
            foreach (var AppInitDll in AppInitDlls.Split(' '))
            {
                Debug.WriteLine("AppInit loading " + AppInitDll);

                // Do not process twice the same imported module
                if (null != PeImports.Find(module => module.Name == AppInitDll))
                {
                    continue;
                }

                if (NewTreeContexts.ContainsKey(AppInitDll))
                {
                    continue;
                }

                ImportContext AppInitImportModule = new ImportContext();
                AppInitImportModule.PeFilePath = null;
                AppInitImportModule.PeProperties = null;
                AppInitImportModule.ModuleName = AppInitDll;
                AppInitImportModule.ApiSetModuleName = null;
                AppInitImportModule.Flags = 0;
                AppInitImportModule.ModuleLocation = ModuleSearchStrategy.AppInitDLL;



                Tuple<ModuleSearchStrategy, PE> ResolvedAppInitModule = BinaryCache.ResolveModule(
                    this._rootModule,
                    AppInitDll,
                    this._sxsEntriesCache,
                    this._customSearchFolders,
                    this._workingDirectory
                );
                if (ResolvedAppInitModule.Item1 != ModuleSearchStrategy.NOT_FOUND)
                {
                    AppInitImportModule.PeProperties = ResolvedAppInitModule.Item2;
                    AppInitImportModule.PeFilePath = ResolvedAppInitModule.Item2.Filepath;
                }
                else
                {
                    AppInitImportModule.Flags |= ModuleFlag.NotFound;
                }

                NewTreeContexts.Add(AppInitDll, AppInitImportModule);
            }
        }

        /// <summary>
		/// Background processing of a single PE file.
		/// It can be lengthy since there are disk access (and misses).
		/// </summary>
		/// <param name="NewTreeContexts"> This variable is passed as reference to be updated since this function is run in a separate thread. </param>
		/// <param name="newPe"> Current PE file analyzed </param>
		private void ProcessPeImports(Dictionary<string, ImportContext> NewTreeContexts, PE newPe)
        {
            List<PeImportDll> PeImports = newPe.GetImports();

            foreach (PeImportDll DllImport in PeImports)
            {
                // Ignore already processed imports
                if (NewTreeContexts.ContainsKey(DllImport.Name))
                {
                    continue;
                }

                // Find Dll in "paths"
                ImportContext ImportModule = ResolveImport(DllImport);

                NewTreeContexts.Add(DllImport.Name, ImportModule);


                // AppInitDlls are triggered by user32.dll, so if the binary does not import user32.dll they are not loaded.
                ProcessAppInitDlls(NewTreeContexts, newPe, ImportModule);


                // if mscoree.dll is imported, it means the module is a C# assembly, and we can use Mono.Cecil to enumerate its references
                //ProcessClrImports(NewTreeContexts, newPe, ImportModule);
            }
        }

        public bool ProcessPe(string path, CancellationToken cancelToken, int recursionLevel)
        {
            if (recursionLevel > 100)
                return false;

            if (cancelToken.IsCancellationRequested)
                return false;

            // "Closured" variables (it 's a scope hack really).
            Dictionary<string, ImportContext> NewTreeContexts = new Dictionary<string, ImportContext>();
            List<string> moduleBackLog = new();

            BackgroundWorker bw = new BackgroundWorker();
            bw.WorkerReportsProgress = true; // useless here for now

            if (!NativeFile.Exists(path))
            {
                return true;
            }

            PE binary = BinaryCache.LoadPe(path);

            if (binary == null || !binary.LoadSuccessful)
            {
                return true;
            }

            bw.DoWork += (sender, e) =>
            {
                _runningWorkers++;

                if (!cancelToken.IsCancellationRequested)
                {
                    ProcessPeImports(NewTreeContexts, binary);
                }
            };

            bw.RunWorkerCompleted += (sender, e) =>
            {
                try
                {
                    foreach (ImportContext NewTreeContext in NewTreeContexts.Values)
                    {
                        if (cancelToken.IsCancellationRequested)
                            return;

                        DependencyNodeContext childTreeNodeContext = new DependencyNodeContext();
                        childTreeNodeContext.IsDummy = false;

                        string identifier;

                        if (NewTreeContext.PeFilePath == null || NewTreeContext.ModuleLocation == ModuleSearchStrategy.NOT_FOUND)
                        {
                            identifier = NewTreeContext.ModuleName;
                        }

                        else
                        {
                            identifier = Path.GetFullPath(NewTreeContext.PeFilePath).ToLowerInvariant();
                        }

                        // Newly seen modules
                        if (!_processedFiles.ContainsKey(identifier))
                        {

                            this._processedFiles[identifier] = NewTreeContext.Flags;

                            if ((NewTreeContext.PeFilePath == null) || !NativeFile.Exists(NewTreeContext.PeFilePath) || NewTreeContext.PeProperties == null)
                            {
                                this._processedFiles[identifier] |= ModuleFlag.NotFound;
                                if (!NewTreeContext.Flags.HasFlag(ModuleFlag.ApiSetExt))
                                {
                                    // Skip ext api sets
                                    AddItem(new NotFoundModuleInfo(NewTreeContext.ModuleName, NewTreeContext.Flags.HasFlag(ModuleFlag.DelayLoad)));
                                }
                            }
                            else
                            {
                                AddItem(new DisplayModuleInfo(NewTreeContext.ModuleName, NewTreeContext.PeProperties, NewTreeContext.ModuleLocation, NewTreeContext.Flags));
                                moduleBackLog.Add(NewTreeContext.PeFilePath);
                            }
                        }
                        else
                        {
                            this._processedFiles[identifier] |= NewTreeContext.Flags;
                        }

                    }

                    foreach (string newModule in moduleBackLog)
                    {
                        if (cancelToken.IsCancellationRequested)
                            return;

                        ProcessPe(newModule, cancelToken, recursionLevel + 1);
                    }
                }
                finally
                {
                    _runningWorkers--;

                    System.Diagnostics.Debug.WriteLine("Worker: " + _runningWorkers);
                    if (_runningWorkers == 0)
                    {
                        ProgressIndicator.Visibility = Visibility.Collapsed;
                    }
                }
            };

            bw.RunWorkerAsync();

            return true;
        }

        public void WindowOpened()
        {
            CancellationTokenSource cts = new CancellationTokenSource();

            Settings.Default.PropertyChanged += Font_PropertyChanged;

            ProcessPe(_filePath, _cts.Token, 0);
        }

        public void WindowClosed()
        {
            Settings.Default.PropertyChanged -= Font_PropertyChanged;

            _cts.Cancel();
            _cts.Dispose();
        }

        private void SelectorBar_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
        {
            bool showNotFound = (sender.SelectedItem.Tag as string) == "Unresolved";
            foreach (var filteredList in _filteredItems.Values)
            {
                using (filteredList.DeferRefresh())
                {
                    filteredList.Filter = showNotFound ? x => (x as DisplayModuleInfo).Flags.HasFlag(ModuleFlag.NotFound) : null;
                }
            }
        }

        private void UpdateFont()
        {
            var listViewContainerStyle = new Style();
            listViewContainerStyle.BasedOn = App.Current.Resources["DefaultListViewItemStyle"] as Style;
            listViewContainerStyle.TargetType = typeof(ListViewItem);
            listViewContainerStyle.Setters.Add(new Setter(FontFamilyProperty, Properties.Settings.Default.Font));
            ItemList.ItemContainerStyle = listViewContainerStyle;
        }

        private void Font_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(Properties.Settings.Default.Font))
            {
                UpdateFont();
            }
        }

        private void SelectAllCommand_ExecuteRequested(XamlUICommand sender, ExecuteRequestedEventArgs args)
        {
            ItemList.SelectAll();
        }

        private void CopyCommand_ExecuteRequested(XamlUICommand sender, ExecuteRequestedEventArgs args)
        {
            DisplayModuleInfo targetItem = null;
            if (args.Parameter is FrameworkElement fe)
            {
                targetItem = fe.DataContext as DisplayModuleInfo;
            }

            StringBuilder stringBuilder = new();

            if (targetItem != null)
            {
                if (!ItemList.SelectedItems.Contains(targetItem))
                {
                    stringBuilder.Append(targetItem.Filepath);
                }
            }

            if (stringBuilder.Length == 0)
            {
                if (ItemList.SelectedItems == null)
                {
                    return;
                }
                else
                {
                    foreach (var item in ItemList.SelectedItems)
                    {
                        if (item is DisplayModuleInfo module)
                        {
                            stringBuilder.AppendLine(module.Filepath);
                        }
                    }
                }
            }

            var str = stringBuilder.ToString();

            DataPackage dataPackage = new DataPackage();
            dataPackage.RequestedOperation = DataPackageOperation.Copy;
            dataPackage.SetText(stringBuilder.ToString());

            try
            {

                Clipboard.SetContent(dataPackage);
                Clipboard.Flush();
            }
            catch { }
        }


        public static void OpenInNewWindow(XamlRoot parent, PE rootModule, List<string> customSearchFolders, SxsEntries sxsEntriesCache, string workingDirectory, string filepath)
        {
            DependenciesListPage listPage = new DependenciesListPage(rootModule, customSearchFolders, sxsEntriesCache, workingDirectory, filepath);

            Window win = new Window();
            win.SystemBackdrop = new MicaBackdrop();
            win.Content = listPage;
            win.ExtendsContentIntoTitleBar = true;
            win.Closed += (o, e) => { listPage.WindowClosed(); };
            win.AppWindow.Resize(new Windows.Graphics.SizeInt32((int)(parent.RasterizationScale * 500), (int)(parent.RasterizationScale * 600)));
            win.Activate();

            listPage.WindowOpened();
        }
    }
}
