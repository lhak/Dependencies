using System;
using System.Diagnostics;
using System.Windows;
using System.Collections.Generic;

using Dependencies;
using Dependencies.ClrPh;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.ApplicationModel.DataTransfer;
using System.Diagnostics.CodeAnalysis;
using WinRT;

[GeneratedBindableCustomProperty]
[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)]
public partial class DisplayPeExport : SettingBindingHandler
{
    # region Constructors
    public DisplayPeExport(
        PeExport PeExport,
        PhSymbolProvider SymPrv
    )
    {
        PeInfo.ordinal = (ushort) PeExport.Ordinal;
        //PeInfo.hint = (ushort) (/*PeExport.Hint*/ PeExport.Ordinal - 1); // @TODO(add hints to exports)
        PeInfo.name = PeExport.Name;
        PeInfo.ForwardName = PeExport.ForwardedName;
        PeInfo.exportByOrdinal = PeExport.ExportByOrdinal;
        PeInfo.forwardedExport = PeExport.ForwardedName.Length > 0;
        PeInfo.exportAsCppName = (PeExport.Name.Length > 0 && PeExport.Name[0] == '?');
        PeInfo.virtualAddress = PeExport.VirtualAddress;
        

        Tuple<CLRPH_DEMANGLER, string> DemanglingInfos = SymPrv.UndecorateName(PeExport.Name);
        PeInfo.Demangler = Enum.GetName(typeof(CLRPH_DEMANGLER), DemanglingInfos.Item1);
        PeInfo.UndecoratedName = DemanglingInfos.Item2;

        AddNewEventHandler("Undecorate", "Undecorate", "Name", this.GetDisplayName);
    }
	#endregion Constructors

	#region PublicAPI
	public override string ToString()
	{
		List<string> members = new List<string>() {
			String.Format("{0} (0x{0:x04})", Ordinal),
			Hint != 0 ? String.Format("{0} (0x{0:x08})", Hint) : "N/A",
			Name,
			VirtualAddress,
			Demangler
		};

		return String.Join(", ", members.ToArray());
	}

    // WinUI uses list view virtualization. To improve performance use a cache
    public BitmapImage CachedIcon
    {
        get
        {
            return (App.Current as App).GetCachedIcon(IconUri);
        }
    }

    public string IconUri
    {
        get
        {
            if (PeInfo.forwardedExport)
                return "Images/export_forward.png";
            if (PeInfo.exportByOrdinal)
                return "Images/export_ord.png";
            if (PeInfo.exportAsCppName)
                return "Images/export_cpp.png";
            
            return "Images/export_C.png";
        }
    }

    public int Type
    {
        get
        {
            if (PeInfo.forwardedExport)
                return 1;
            if (PeInfo.exportByOrdinal)
                return 2;
            if (PeInfo.exportAsCppName)
                return 3;

            return 0;
        }
    }
    public ushort ? Hint
    {
        get
        {
            return null;
        }
    }

    public ushort Ordinal { get { return PeInfo.ordinal; } }

    public string Name
    {
        get { return GetDisplayName(Dependencies.Properties.Settings.Default.Undecorate); }
    }

    public string VirtualAddress
    {
        get
        {
            if (PeInfo.forwardedExport)
                return PeInfo.ForwardName;
            return String.Format("0x{0:x8}", PeInfo.virtualAddress);
        }
    }

    public string Demangler { get { return PeInfo.Demangler; } }

    protected string GetDisplayName(bool Undecorate)
    { 
        if (PeInfo.exportByOrdinal)
            return String.Format("Ordinal_{0:d}", PeInfo.ordinal);


        if ((Undecorate) && (PeInfo.UndecoratedName.Length > 0))
            return PeInfo.UndecoratedName;

        return PeInfo.name;
        
    }
#endregion PublicAPI

#region Commands 
    public RelayCommand QueryExportApi
    {
        get
        {
            if (_QueryExportApi == null)
            {
                _QueryExportApi = new RelayCommand((param) =>
                {
                    if ((param == null))
                    {
                        return;
                    }

                    string ExportName = (param as DisplayPeExport).Name;
                    if (ExportName == null)
                    {
                        return;
                    }

                    Process.Start(new ProcessStartInfo() { FileName = @"https://docs.microsoft.com/search/?search=" + ExportName, UseShellExecute = true });
                });
            }

            return _QueryExportApi;
        }
    }
    public RelayCommand CopyValue
    {
        get
        {
            if (_CopyValue == null)
            {
                _CopyValue = new RelayCommand((param) =>
                {
                    if ((param == null))
                    {
                        return;
                    }

                    DataPackage dataPackage = new DataPackage();
                    dataPackage.RequestedOperation = DataPackageOperation.Copy;
                    dataPackage.SetText(param.ToString());

                    try
                    {

                        Clipboard.SetContent(dataPackage);
                        Clipboard.Flush();
                    }
                    catch { }
                });
            }

            return _CopyValue;
        }
    }

#endregion // Commands 


    private PeExportInfo PeInfo;
    private RelayCommand _QueryExportApi;
    private RelayCommand _CopyValue;
}

public struct PeExportInfo
{
    public Boolean exportByOrdinal;
    public Boolean exportAsCppName;
    public Boolean forwardedExport;
    public ushort ordinal;
    //public ushort hint;
    public long virtualAddress;
    public string name;
    public string ForwardName;
    public string UndecoratedName;
    public string Demangler;
}