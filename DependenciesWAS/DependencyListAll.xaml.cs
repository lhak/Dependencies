using Dependencies.ClrPh;
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
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;

namespace Dependencies
{

    public sealed partial class DependencyListAll : Page
    {
        public DependencyListAll()
        {
            _processedFiles = new();
            this.InitializeComponent();
        }

        PE _rootModule;
        List<string> _customSearchFolders;
        string _workingDirectory;
        SxsEntries _sxsEntriesCache;
        Dictionary<string, ModuleFlag> _processedFiles;

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
                    foreach (var Import in BinaryCache.LookupImports(DllImport, ImportModule.PeFilePath))
                    {
                        if (!Import.Item2)
                        {
                            ImportModule.Flags |= ModuleFlag.MissingImports;
                            break;
                        }

                    }
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
                //ProcessAppInitDlls(NewTreeContexts, newPe, ImportModule);


                // if mscoree.dll is imported, it means the module is a C# assembly, and we can use Mono.Cecil to enumerate its references
                //ProcessClrImports(NewTreeContexts, newPe, ImportModule);
            }
        }

        public bool ProcessPe(string path, int recursionLevel)
        {
            if (recursionLevel > 20)
                return false;

            // "Closured" variables (it 's a scope hack really).
            Dictionary<string, ImportContext> NewTreeContexts = new Dictionary<string, ImportContext>();
            List<string> moduleBackLog = new();

            PE binary = (Application.Current as App).LoadBinary(path);

            if (binary == null)
            {
                return true;
            }

            ProcessPeImports(NewTreeContexts, binary);


            foreach (ImportContext NewTreeContext in NewTreeContexts.Values)
            {
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


                //string ModuleName = NewTreeContext.ModuleName;
                //string ModuleFilePath = NewTreeContext.PeFilePath;
                //ModuleCacheKey ModuleKey = new ModuleCacheKey(, null, NewTreeContext.Flags);

                // Newly seen modules
                if (!_processedFiles.ContainsKey(identifier))
                {

                    this._processedFiles[identifier] = NewTreeContext.Flags;


                    // Missing module "found"
                    if ((NewTreeContext.PeFilePath == null) || !NativeFile.Exists(NewTreeContext.PeFilePath))
                    {
                        this._processedFiles[identifier] |= ModuleFlag.NotFound;
                    }
                    else
                    {
                        moduleBackLog.Add(NewTreeContext.PeFilePath);
                    }
                }
                else
                {
                    this._processedFiles[identifier] |= NewTreeContext.Flags;
                }

            }

            bool allProcessed = true;

            foreach (string newModule in moduleBackLog)
            {
                if (ProcessPe(newModule, recursionLevel + 1) == false)
                {
                    allProcessed = false;
                }
            }

            return allProcessed;
        }


        public void SetPe(PE rootModule, List<string> customSearchFolders, SxsEntries sxsEntriesCache, string workingDirectory)
        {
            _rootModule = rootModule;
            _customSearchFolders = customSearchFolders;
            _sxsEntriesCache = sxsEntriesCache;
            _workingDirectory = workingDirectory;


            bool allProcessed = ProcessPe(_rootModule.Filepath, 0);



        }
    }
}
