# Win10userspace

print the user address space layout of Windows 10 64-bit system

Usage
python vol.py -f <dump file> --profile <profile> win10userspace -p <pid>,<pid>,<pid>,...
  
  
Tested Operating Systems
Windows 10x64 14393
Windows 10x64 15063
Windows 10x64 16299
Windows 10x64 17134
Windows 10x64 17763
Windows 10x64 18362
Windows 10x64 19041


Output Example
User Allocations
Start        End           Used     Size      Permission         Type           Description
------------ ------------  -------- --------  -----------------  -------------  -----------------------------
00007ffe0000 00007ffe0fff  00001000 00001000  READONLY           Private        
00007ffe6000 00007ffe6fff  00001000 00001000  READONLY           Private        
00f610af0000 00f610beffff  00005000 00100000  READWRITE          Private        Stack of Thread 0
00f610c00000 00f610dfffff  00031000 00200000  READWRITE          Private        PEB0xf610d27000L TEB0xf610d28000L TEB0xf610d2a000L TEB0xf610d2c000L TEB0xf610d2e000L TEB0xf610d30000L TEB0xf610d32000L TEB0xf610d34000L TEB0xf610d38000L TEB0xf610d3a000L TEB0xf610d3c000L TEB0xf610d3e000L TEB0xf610d40000L TEB0xf610d42000L TEB0xf610d44000L TEB0xf610d46000L TEB0xf610d48000L TEB0xf610d4a000L TEB0xf610d4c000L TEB0xf610d4e000L TEB0xf610d50000L TEB0xf610d52000L TEB0xf610d54000L TEB0xf610d56000L TEB0xf610d58000L
00f610e00000 00f610efffff  00002000 00100000  READWRITE          Private        Stack of Thread 1
00f610f00000 00f610ffffff  00002000 00100000  READWRITE          Private        Stack of Thread 2
00f611000000 00f6110fffff  00008000 00100000  READWRITE          Private        Stack of Thread 3
00f611100000 00f6111fffff  00001000 00100000  READWRITE          Private        Stack of Thread 4
00f611200000 00f6112fffff  00005000 00100000  READWRITE          Private        Stack of Thread 5
00f611300000 00f6113fffff  00012000 00100000  READWRITE          Private        Stack of Thread 6
00f611400000 00f6114fffff  00007000 00100000  READWRITE          Private        
00f611500000 00f6115fffff  00002000 00100000  READWRITE          Private        Stack of Thread 7
00f611600000 00f6116fffff  00002000 00100000  READWRITE          Private        Stack of Thread 8
00f611700000 00f6117fffff  00002000 00100000  READWRITE          Private        Stack of Thread 9
00f611800000 00f6118fffff  00004000 00100000  READWRITE          Private        Stack of Thread 11
00f611900000 00f6119fffff  00003000 00100000  READWRITE          Private        Stack of Thread 12
00f611a00000 00f611afffff  00004000 00100000  READWRITE          Private        Stack of Thread 13
00f611b00000 00f611bfffff  00004000 00100000  READWRITE          Private        Stack of Thread 14
00f611c00000 00f611cfffff  00004000 00100000  READWRITE          Private        Stack of Thread 15
00f611d00000 00f611dfffff  00004000 00100000  READWRITE          Private        Stack of Thread 16
00f611e00000 00f611efffff  00004000 00100000  READWRITE          Private        Stack of Thread 17
00f611f00000 00f611ffffff  00004000 00100000  READWRITE          Private        Stack of Thread 18
00f612000000 00f6120fffff  00004000 00100000  READWRITE          Private        Stack of Thread 19
00f612100000 00f6121fffff  00002000 00100000  READWRITE          Private        Stack of Thread 20
00f612200000 00f6122fffff  00002000 00100000  READWRITE          Private        Stack of Thread 21
00f612300000 00f6123fffff  00003000 00100000  READWRITE          Private        Stack of Thread 22
00f612400000 00f6124fffff  00002000 00100000  READWRITE          Private        Stack of Thread 23
02b0ab4f0000 02b0ab4fffff  00001000 00010000  READWRITE          Shared         Heap 1 NT Heap
02b0ab500000 02b0ab50afff  00003000 0000b000  READWRITE          Private        Heap 2 Segment Heap
02b0ab510000 02b0ab52afff  0001b000 0001b000  READONLY           Shared         ApiSetMap
02b0ab530000 02b0ab533fff  00003000 00004000  READONLY           Shared         Section - PID 00432, Name 
02b0ab540000 02b0ab541fff  00002000 00002000  READWRITE          Private        pShimData
02b0ab550000 02b0ab550fff  00001000 00001000  READONLY           Shared         Section - PID 03208, Name __ComCatalogCache__
02b0ab560000 02b0ab56afff  00004000 0000b000  READWRITE          Private        Heap 0 Segment Heap
02b0b1d20000 02b0b1dc3fff  00006000 000a4000  READONLY           Shared         \Windows\System32\zh-CN\KernelBase.dll.mui
7ff683320000 7ff683732fff  00194000 00413000  EXECUTE_WRITECOPY  Shared         \Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1812.10048.0_x64__8wekyb3d8bbwe\Calculator.exe
7fff63010000 7fff63441fff  00160000 00432000  EXECUTE_WRITECOPY  Shared         \Program Files\WindowsApps\Microsoft.UI.Xaml.2.0_2.1810.18004.0_x64__8wekyb3d8bbwe\Microsoft.UI.Xaml.dll
7fff669d0000 7fff66a2efff  0001b000 0005f000  EXECUTE_WRITECOPY  Shared         \Windows\System32\CryptoWinRT.dll
7fff70dd0000 7fff70e0afff  00028000 0003b000  EXECUTE_WRITECOPY  Shared         \Windows\System32\rometadata.dll
7fff74f40000 7fff74f53fff  00010000 00014000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.Globalization.Fontgroups.dll
7fff75070000 7fff750c3fff  00038000 00054000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.Storage.ApplicationData.dll
7fff75d70000 7fff75e55fff  0002f000 000e6000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.UI.Core.TextInput.dll
7fff77800000 7fff778c8fff  0001e000 000c9000  EXECUTE_WRITECOPY  Shared         \Windows\System32\windows.applicationmodel.datatransfer.dll
7fff77cb0000 7fff77d6efff  00027000 000bf000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.Web.dll
7fff78b10000 7fff78b49fff  00019000 0003a000  EXECUTE_WRITECOPY  Shared         \Windows\System32\DataExchange.dll
7fff7aff0000 7fff7b090fff  00026000 000a1000  EXECUTE_WRITECOPY  Shared         \Windows\System32\twinapi.dll
7fff7b0c0000 7fff7b0d8fff  00012000 00019000  EXECUTE_WRITECOPY  Shared         \Windows\System32\execmodelproxy.dll
7fff7c160000 7fff7c20afff  00021000 000ab000  EXECUTE_WRITECOPY  Shared         \Windows\System32\UiaManager.dll
7fff7cb70000 7fff7cb8cfff  0000e000 0001d000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.Shell.ServiceHostBuilder.dll
7fff7dda0000 7fff7ddddfff  00029000 0003e000  EXECUTE_WRITECOPY  Shared         \Windows\System32\wuceffects.dll
7fff7f310000 7fff7f357fff  00029000 00048000  EXECUTE_WRITECOPY  Shared         \Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.29231.0_x64__8wekyb3d8bbwe\concrt140_app.dll
7fff7f510000 7fff7f59cfff  0003f000 0008d000  EXECUTE_WRITECOPY  Shared         \Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.29231.0_x64__8wekyb3d8bbwe\msvcp140_app.dll
7fff7f5a0000 7fff7f5f0fff  00025000 00051000  EXECUTE_WRITECOPY  Shared         \Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.29231.0_x64__8wekyb3d8bbwe\vccorlib140_app.dll
7fff7f600000 7fff7f618fff  0000b000 00019000  EXECUTE_WRITECOPY  Shared         \Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.29231.0_x64__8wekyb3d8bbwe\vcruntime140_app.dll
7fff7f660000 7fff7f691fff  0001d000 00032000  EXECUTE_WRITECOPY  Shared         \Windows\System32\WinRtTracing.dll
7fff7f730000 7fff7f743fff  0000e000 00014000  EXECUTE_WRITECOPY  Shared         \Windows\System32\threadpoolwinrt.dll
7fff80080000 7fff8015dfff  00022000 000de000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.ApplicationModel.dll
7fff802a0000 7fff802a9fff  00007000 0000a000  EXECUTE_WRITECOPY  Shared         \Windows\System32\fontgroupsoverride.dll
7fff82ad0000 7fff82b01fff  0001c000 00032000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.Energy.dll
7fff83cb0000 7fff84154fff  000e5000 004a5000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.UI.Xaml.Controls.dll
7fff84160000 7fff8525cfff  00593000 010fd000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.UI.Xaml.dll
7fff85aa0000 7fff85d9ffff  000e1000 00300000  EXECUTE_WRITECOPY  Shared         \Windows\System32\DWrite.dll
7fff85e80000 7fff85fb3fff  00071000 00134000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.UI.Xaml.Phone.dll
7fff85fc0000 7fff86177fff  00044000 001b8000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.Globalization.dll
7fff86180000 7fff86281fff  0002d000 00102000  EXECUTE_WRITECOPY  Shared         \Windows\System32\InputHost.dll
7fff86290000 7fff8632dfff  0002c000 0009e000  EXECUTE_WRITECOPY  Shared         \Windows\System32\TextInputFramework.dll
7fff863a0000 7fff864b1fff  00075000 00112000  EXECUTE_WRITECOPY  Shared         \Windows\System32\MrmCoreR.dll
7fff86500000 7fff8655cfff  00029000 0005d000  EXECUTE_WRITECOPY  Shared         \Windows\System32\BCP47Langs.dll
7fff86610000 7fff86760fff  000a9000 00151000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.UI.dll
7fff86770000 7fff8677ffff  00009000 00010000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.StateRepositoryCore.dll
7fff867d0000 7fff86868fff  00044000 00099000  EXECUTE_WRITECOPY  Shared         \Windows\System32\directmanipulation.dll
7fff868a0000 7fff86a73fff  0002b000 001d4000  EXECUTE_WRITECOPY  Shared         \Windows\System32\urlmon.dll
7fff86a80000 7fff86b90fff  0002f000 00111000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.UI.Immersive.dll
7fff86ba0000 7fff86e45fff  000b2000 002a6000  EXECUTE_WRITECOPY  Shared         \Windows\System32\iertutil.dll
7fff86e50000 7fff86e7ffff  00020000 00030000  EXECUTE_WRITECOPY  Shared         \Windows\System32\BCP47mrm.dll
7fff87e50000 7fff87e5bfff  00007000 0000c000  EXECUTE_WRITECOPY  Shared         \Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.29231.0_x64__8wekyb3d8bbwe\vcruntime140_1_app.dll
7fff89db0000 7fff89dd9fff  00008000 0002a000  EXECUTE_WRITECOPY  Shared         \Windows\System32\dbgcore.dll
7fff89de0000 7fff89fd3fff  00030000 001f4000  EXECUTE_WRITECOPY  Shared         \Windows\System32\dbghelp.dll
7fff89fe0000 7fff8a02afff  0003f000 0004b000  EXECUTE_WRITECOPY  Shared         \Windows\System32\vm3dum64_10.dll
7fff8a060000 7fff8a078fff  00012000 00019000  EXECUTE_WRITECOPY  Shared         \Windows\System32\vm3dum64_loader.dll
7fff8a080000 7fff8a105fff  0002d000 00086000  EXECUTE_WRITECOPY  Shared         \Windows\System32\Windows.Graphics.dll
7fff8a720000 7fff8a729fff  00005000 0000a000  EXECUTE_WRITECOPY  Shared         \Windows\System32\version.dll
7fff8a940000 7fff8b0a8fff  00404000 00769000  EXECUTE_WRITECOPY  Shared         \Windows\System32\OneCoreUAPCommonProxyStub.dll
7fff8b0d0000 7fff8b111fff  00014000 00042000  EXECUTE_WRITECOPY  Shared         \Windows\System32\logoncli.dll
7fff8b490000 7fff8b4f4fff  00032000 00065000  EXECUTE_WRITECOPY  Shared         \Windows\System32\ninput.dll
7fff8b500000 7fff8b828fff  000b8000 00329000  EXECUTE_WRITECOPY  Shared         \Windows\System32\CoreUIComponents.dll
7fff8c370000 7fff8c92ffff  000e5000 005c0000  EXECUTE_WRITECOPY  Shared         \Windows\System32\d2d1.dll
7fff8c930000 7fff8c95cfff  0000f000 0002d000  EXECUTE_WRITECOPY  Shared         \Windows\System32\winmmbase.dll
7fff8c960000 7fff8c983fff  0000f000 00024000  EXECUTE_WRITECOPY  Shared         \Windows\System32\winmm.dll
7fff8cec0000 7fff8d11afff  000e9000 0025b000  EXECUTE_WRITECOPY  Shared         \Windows\System32\d3d11.dll
7fff8d120000 7fff8d2fafff  000c7000 001db000  EXECUTE_WRITECOPY  Shared         \Windows\System32\dcomp.dll
7fff8d300000 7fff8d3d3fff  00078000 000d4000  EXECUTE_WRITECOPY  Shared         \Windows\System32\CoreMessaging.dll
7fff8dbc0000 7fff8dd12fff  00093000 00153000  EXECUTE_WRITECOPY  Shared         \Windows\System32\WinTypes.dll
7fff8e550000 7fff8e63efff  0001d000 000ef000  EXECUTE_WRITECOPY  Shared         \Windows\System32\propsys.dll
7fff8e6e0000 7fff8e88efff  00077000 001af000  EXECUTE_WRITECOPY  Shared         \Windows\System32\WindowsCodecs.dll
7fff8e9c0000 7fff8ea58fff  00033000 00099000  EXECUTE_WRITECOPY  Shared         \Windows\System32\uxtheme.dll
7fff8ea80000 7fff8ecd9fff  000cd000 0025a000  EXECUTE_WRITECOPY  Shared         \Windows\System32\twinapi.appcore.dll
7fff8ede0000 7fff8ee08fff  00012000 00029000  EXECUTE_WRITECOPY  Shared         \Windows\System32\rmclient.dll
7fff8efb0000 7fff8efdcfff  00012000 0002d000  EXECUTE_WRITECOPY  Shared         \Windows\System32\dwmapi.dll
7fff8f2b0000 7fff8f2cffff  00010000 00020000  EXECUTE_WRITECOPY  Shared         \Windows\System32\DXCore.dll
7fff8f340000 7fff8f429fff  00042000 000ea000  EXECUTE_WRITECOPY  Shared         \Windows\System32\dxgi.dll
7fff8f6a0000 7fff8f6d0fff  0000f000 00031000  EXECUTE_WRITECOPY  Shared         \Windows\System32\ntmarta.dll
7fff8f6e0000 7fff8f706fff  0000e000 00027000  EXECUTE_WRITECOPY  Shared         \Windows\System32\profext.dll
7fff90030000 7fff9003bfff  00008000 0000c000  EXECUTE_WRITECOPY  Shared         \Windows\System32\cryptbase.dll
7fff904e0000 7fff90504fff  00010000 00025000  EXECUTE_WRITECOPY  Shared         \Windows\System32\userenv.dll
7fff905f0000 7fff905fffff  00009000 00010000  EXECUTE_WRITECOPY  Shared         \Windows\System32\umpdc.dll
7fff90620000 7fff90669fff  0000c000 0004a000  EXECUTE_WRITECOPY  Shared         \Windows\System32\powrprof.dll
7fff90670000 7fff90680fff  0000d000 00011000  EXECUTE_WRITECOPY  Shared         \Windows\System32\kernel.appcore.dll
7fff90690000 7fff906aefff  00010000 0001f000  EXECUTE_WRITECOPY  Shared         \Windows\System32\profapi.dll
7fff906b0000 7fff9074dfff  00033000 0009e000  EXECUTE_WRITECOPY  Shared         \Windows\System32\msvcp_win.dll
7fff90750000 7fff907d0fff  00020000 00081000  EXECUTE_WRITECOPY  Shared         \Windows\System32\bcryptprimitives.dll
7fff907e0000 7fff90800fff  0001e000 00021000  EXECUTE_WRITECOPY  Shared         \Windows\System32\win32u.dll
7fff90810000 7fff909a3fff  00030000 00194000  EXECUTE_WRITECOPY  Shared         \Windows\System32\gdi32full.dll
7fff90a60000 7fff90b59fff  00055000 000fa000  EXECUTE_WRITECOPY  Shared         \Windows\System32\ucrtbase.dll
7fff90b60000 7fff90b76fff  0000a000 00017000  EXECUTE_WRITECOPY  Shared         \Windows\System32\cryptsp.dll
7fff90b80000 7fff912fafff  0008f000 0077b000  EXECUTE_WRITECOPY  Shared         \Windows\System32\windows.storage.dll
7fff914b0000 7fff91752fff  000b4000 002a3000  EXECUTE_WRITECOPY  Shared         \Windows\System32\KernelBase.dll
7fff91760000 7fff91785fff  00010000 00026000  EXECUTE_WRITECOPY  Shared         \Windows\System32\bcrypt.dll
7fff91790000 7fff917d9fff  00011000 0004a000  EXECUTE_WRITECOPY  Shared         \Windows\System32\cfgmgr32.dll
7fff917e0000 7fff91876fff  0002d000 00097000  EXECUTE_WRITECOPY  Shared         \Windows\System32\sechost.dll
7fff91880000 7fff91f5ffff  00043000 006e0000  EXECUTE_WRITECOPY  Shared         \Windows\System32\shell32.dll
7fff91f70000 7fff92033fff  0001f000 000c4000  EXECUTE_WRITECOPY  Shared         \Windows\System32\oleaut32.dll
7fff92100000 7fff921a2fff  0001f000 000a3000  EXECUTE_WRITECOPY  Shared         \Windows\System32\advapi32.dll
7fff92230000 7fff923c2fff  00053000 00193000  EXECUTE_WRITECOPY  Shared         \Windows\System32\user32.dll
7fff925f0000 7fff92726fff  0005b000 00137000  EXECUTE_WRITECOPY  Shared         \Windows\System32\msctf.dll
7fff92730000 7fff9284ffff  0009b000 00120000  EXECUTE_WRITECOPY  Shared         \Windows\System32\rpcrt4.dll
7fff92860000 7fff92911fff  0003e000 000b2000  EXECUTE_WRITECOPY  Shared         \Windows\System32\kernel32.dll
7fff92d90000 7fff930c5fff  00191000 00336000  EXECUTE_WRITECOPY  Shared         \Windows\System32\combase.dll
7fff930d0000 7fff93178fff  0005d000 000a9000  EXECUTE_WRITECOPY  Shared         \Windows\System32\SHCore.dll
7fff932a0000 7fff932cdfff  0000f000 0002e000  EXECUTE_WRITECOPY  Shared         \Windows\System32\imm32.dll
7fff932f0000 7fff93341fff  0001d000 00052000  EXECUTE_WRITECOPY  Shared         \Windows\System32\shlwapi.dll
7fff93360000 7fff93385fff  00020000 00026000  EXECUTE_WRITECOPY  Shared         \Windows\System32\gdi32.dll
7fff93390000 7fff93405fff  0000f000 00076000  EXECUTE_WRITECOPY  Shared         \Windows\System32\coml2.dll
7fff934e0000 7fff9357dfff  0004f000 0009e000  EXECUTE_WRITECOPY  Shared         \Windows\System32\msvcrt.dll
7fff93580000 7fff936d5fff  0002f000 00156000  EXECUTE_WRITECOPY  Shared         \Windows\System32\ole32.dll
7fff93720000 7fff9390ffff  000fd000 001f0000  EXECUTE_WRITECOPY  Shared         \Windows\System32\ntdll.dll
