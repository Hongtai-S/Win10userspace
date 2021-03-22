import json
import struct
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.taskmods as taskmods
import volatility.plugins.handles as handles
import volatility.obj as obj
import volatility.utils as utils
import volatility.debug as debug
import volatility.constants as constants
import volatility.plugins.filescan as filescan
from volatility.plugins.common import AbstractWindowsCommand
import volatility.win32.tasks as vtasks


class Win10userspace(AbstractWindowsCommand):
    """Traversing the accessible memory areas in the user address space"""

    def __init__(self, config, *args, **kwargs):

        AbstractWindowsCommand.__init__(self, config, *args,**kwargs)

        self._config.add_option('PID', short_option = 'p', default = None,
                      help = 'Operate on these Process IDs (comma-separated)',
                      action = 'store', type = 'str')
        self.addr_space = utils.load_as(self._config)

        #Import the segment heap data structure
        if self._config.profile == 'Win10x64_17763':
            self.addr_space.profile.add_types({
                '_SEGMENT_HEAP': [0x7c0, {
                    'EnvHandle': [0x0, ['RTL_HP_ENV_HANDLE']],
                    'Signature': [0x10, ['unsigned long']],
                    'GlobalFlags': [0x14, ['unsigned long']],
                    'Interceptor': [0x18, ['unsigned long']],
                    'ProcessHeapListIndex': [0x1c, ['unsigned short']],
                    'AllocatedFromMetadata': [0x1e,
                                              ['BitField', dict(start_bit=0, end_bit=1, native_type='unsigned short')]],
                    'CommitLimitData': [0x20, ['_RTL_HEAP_MEMORY_LIMIT_DATA']],
                    'LargeMetadataLock': [0x40, ['unsigned long long']],
                    'LargeAllocMetadata': [0x48, ['_RTL_RB_TREE']],
                    'LargeReservedPages': [0x58, ['unsigned long long']],
                    'LargeCommittedPages': [0x60, ['unsigned long long']],
                    'StackTraceInitVar': [0x68, ['_RTL_RUN_ONCE']],
                    'MemStats': [0x80, ['_HEAP_RUNTIME_MEMORY_STATS']],
                    'GlobalLockCount': [0xd8, ['unsigned short']],
                    'GlobalLockOwner': [0xdc, ['unsigned long']],
                    'ContextExtendLock': [0xe0, ['unsigned long long']],
                    'AllocatedBase': [0xe8, ['pointer64', ['unsigned char']]],
                    'UncommittedBase': [0xf0, ['pointer64', ['unsigned char']]],
                    'ReservedLimit': [0xf8, ['pointer64', ['unsigned char']]],
                    'SegContexts': [0x100, ['array', 2, ['_HEAP_SEG_CONTEXT']]],
                    'VsContext': [0x280, ['_HEAP_VS_CONTEXT']],
                    'LfhContext': [0x300, ['_HEAP_LFH_CONTEXT']],
                }],
                '_HEAP_SEG_CONTEXT': [0xc0, {
                    'SegmentMask': [0x0, ['unsigned long long']],
                    'UnitShift': [0x8, ['unsigned char']],
                    'PagesPerUnitShift': [0x9, ['unsigned char']],
                    'FirstDescriptorIndex': [0xa, ['unsigned char']],
                    'CachedCommitSoftShift': [0xb, ['unsigned char']],
                    'CachedCommitHighShift': [0xc, ['unsigned char']],
                    'Flags': [0xd, ['__unnamed_1833']],
                    'MaxAllocationSize': [0x10, ['unsigned long']],
                    'OlpStatsOffset': [0x14, ['short']],
                    'MemStatsOffset': [0x16, ['short']],
                    'LfhContext': [0x18, ['pointer64', ['void']]],
                    'VsContext': [0x20, ['pointer64', ['void']]],
                    'EnvHandle': [0x28, ['RTL_HP_ENV_HANDLE']],
                    'Heap': [0x38, ['pointer64', ['void']]],
                    'SegmentLock': [0x40, ['unsigned long long']],
                    'SegmentListHead': [0x48, ['_LIST_ENTRY']],
                    'SegmentCount': [0x58, ['unsigned long long']],
                    'FreePageRanges': [0x60, ['_RTL_RB_TREE']],
                    'FreeSegmentListLock': [0x70, ['unsigned long long']],
                    'FreeSegmentList': [0x78, ['array', 2, ['_SINGLE_LIST_ENTRY']]],
                }],
                '_HEAP_LARGE_ALLOC_DATA': [0x28, {
                    'TreeNode': [0x0, ['_RTL_BALANCED_NODE']],
                    'VirtualAddress': [0x18, ['unsigned long long']],
                    'UnusedBytes': [0x18,
                                    ['BitField', dict(start_bit=0, end_bit=16, native_type='unsigned long long')]],
                    'ExtraPresent': [0x20,
                                     ['BitField', dict(start_bit=0, end_bit=1, native_type='unsigned long long')]],
                    'GuardPageCount': [0x20,
                                       ['BitField', dict(start_bit=1, end_bit=2, native_type='unsigned long long')]],
                    'GuardPageAlignment': [0x20, ['BitField',
                                                  dict(start_bit=2, end_bit=8, native_type='unsigned long long')]],
                    'Spare': [0x20, ['BitField', dict(start_bit=8, end_bit=12, native_type='unsigned long long')]],
                    'AllocatedPages': [0x20,
                                       ['BitField', dict(start_bit=12, end_bit=64, native_type='unsigned long long')]],
                }]
            })

        if self._config.profile == 'Win10x64_17134':
            self.addr_space.profile.add_types({
                '_SEGMENT_HEAP': [0x6f0, {
                    'EnvHandle': [0x0, ['RTL_HP_ENV_HANDLE']],
                    'Signature': [0x10, ['unsigned long']],
                    'GlobalFlags': [0x14, ['unsigned long']],
                    'MemStats': [0x18, ['_HEAP_RUNTIME_MEMORY_STATS']],
                    'Interceptor': [0x38, ['unsigned long']],
                    'ProcessHeapListIndex': [0x3c, ['unsigned short']],
                    'GlobalLockCount': [0x3e, ['unsigned short']],
                    'GlobalLockOwner': [0x40, ['unsigned long']],
                    'AllocatedFromMetadata': [0x44,
                                              ['BitField', dict(start_bit=0, end_bit=1, native_type='unsigned long')]],
                    'LargeMetadataLock': [0x48, ['unsigned long long']],
                    'LargeAllocMetadata': [0x50, ['_RTL_RB_TREE']],
                    'LargeReservedPages': [0x60, ['unsigned long long']],
                    'LargeCommittedPages': [0x68, ['unsigned long long']],
                    'SegContexts': [0x70, ['array', 2, ['_HEAP_SEG_CONTEXT']]],
                    'StackTraceInitVar': [0x160, ['_RTL_RUN_ONCE']],
                    'ContextExtendLock': [0x168, ['unsigned long long']],
                    'AllocatedBase': [0x170, ['pointer64', ['unsigned char']]],
                    'UncommittedBase': [0x178, ['pointer64', ['unsigned char']]],
                    'ReservedLimit': [0x180, ['pointer64', ['unsigned char']]],
                    'VsContext': [0x188, ['_HEAP_VS_CONTEXT']],
                    'LfhContext': [0x200, ['_HEAP_LFH_CONTEXT']],
                }],
                '_HEAP_SEG_CONTEXT': [0x78, {
                    'SegmentMask': [0x0, ['unsigned long long']],
                    'UnitShift': [0x8, ['unsigned char']],
                    'PagesPerUnitShift': [0x9, ['unsigned char']],
                    'FirstDescriptorIndex': [0xa, ['unsigned char']],
                    'CachedCommitSoftShift': [0xb, ['unsigned char']],
                    'CachedCommitHighShift': [0xc, ['unsigned char']],
                    'Flags': [0xd, ['__unnamed_180f']],
                    'MaxAllocationSize': [0x10, ['unsigned long']],
                    'SegmentLock': [0x18, ['unsigned long long']],
                    'SegmentListHead': [0x20, ['_LIST_ENTRY']],
                    'SegmentCount': [0x30, ['unsigned long long']],
                    'FreePageRanges': [0x38, ['_RTL_RB_TREE']],
                    'MemStats': [0x48, ['pointer64', ['_HEAP_RUNTIME_MEMORY_STATS']]],
                    'LfhContext': [0x50, ['pointer64', ['void']]],
                    'VsContext': [0x58, ['pointer64', ['void']]],
                    'EnvHandle': [0x60, ['RTL_HP_ENV_HANDLE']],
                    'Heap': [0x70, ['pointer64', ['void']]],
                }],
                '_HEAP_LARGE_ALLOC_DATA': [0x28, {
                    'TreeNode': [0x0, ['_RTL_BALANCED_NODE']],
                    'VirtualAddress': [0x18, ['unsigned long long']],
                    'UnusedBytes': [0x18,
                                    ['BitField', dict(start_bit=0, end_bit=16, native_type='unsigned long long')]],
                    'ExtraPresent': [0x20,
                                     ['BitField', dict(start_bit=0, end_bit=1, native_type='unsigned long long')]],
                    'GuardPageCount': [0x20,
                                       ['BitField', dict(start_bit=1, end_bit=2, native_type='unsigned long long')]],
                    'GuardPageAlignment': [0x20, ['BitField',
                                                  dict(start_bit=2, end_bit=8, native_type='unsigned long long')]],
                    'Spare': [0x20, ['BitField', dict(start_bit=8, end_bit=12, native_type='unsigned long long')]],
                    'AllocatedPages': [0x20,
                                       ['BitField', dict(start_bit=12, end_bit=64, native_type='unsigned long long')]],
                }]
            })
        if self._config.profile == 'Win10x64_16299':
            self.addr_space.profile.add_types({
                '_SEGMENT_HEAP': [0x6c0, {
                    'Padding': [0x0, ['array', 2, ['pointer64', ['void']]]],
                    'Signature': [0x10, ['unsigned long']],
                    'GlobalFlags': [0x14, ['unsigned long']],
                    'MemStats': [0x18, ['_HEAP_RUNTIME_MEMORY_STATS']],
                    'Interceptor': [0x38, ['unsigned long']],
                    'ProcessHeapListIndex': [0x3c, ['unsigned short']],
                    'GlobalLockCount': [0x3e, ['unsigned short']],
                    'GlobalLockOwner': [0x40, ['unsigned long']],
                    'LargeMetadataLock': [0x48, ['_RTL_SRWLOCK']],
                    'LargeAllocMetadata': [0x50, ['_RTL_RB_TREE']],
                    'LargeReservedPages': [0x60, ['unsigned long long']],
                    'LargeCommittedPages': [0x68, ['unsigned long long']],
                    'SegContexts': [0x70, ['array', 2, ['_HEAP_SEG_CONTEXT']]],
                    'StackTraceInitVar': [0x140, ['_RTL_RUN_ONCE']],
                    'ContextExtendLock': [0x148, ['_RTL_SRWLOCK']],
                    'AllocatedBase': [0x150, ['pointer64', ['unsigned char']]],
                    'UncommittedBase': [0x158, ['pointer64', ['unsigned char']]],
                    'ReservedLimit': [0x160, ['pointer64', ['unsigned char']]],
                    'VsContext': [0x168, ['_HEAP_VS_CONTEXT']],
                    'LfhContext': [0x1e0, ['_HEAP_LFH_CONTEXT']],
                }],
                '_HEAP_SEG_CONTEXT': [0x68, {
                    'SegmentMask': [0x0, ['unsigned long long']],
                    'UnitShift': [0x8, ['unsigned char']],
                    'PagesPerUnitShift': [0x9, ['unsigned char']],
                    'FirstDescriptorIndex': [0xa, ['unsigned char']],
                    'CachedCommitSoftShift': [0xb, ['unsigned char']],
                    'CachedCommitHighShift': [0xc, ['unsigned char']],
                    'MaxAllocationSize': [0x10, ['unsigned long']],
                    'SegmentLock': [0x18, ['_RTL_SRWLOCK']],
                    'SegmentListHead': [0x20, ['_LIST_ENTRY']],
                    'SegmentCount': [0x30, ['unsigned long long']],
                    'FreePageRanges': [0x38, ['_RTL_RB_TREE']],
                    'MemStats': [0x48, ['pointer64', ['_HEAP_RUNTIME_MEMORY_STATS']]],
                    'LfhContext': [0x50, ['pointer64', ['void']]],
                    'VsContext': [0x58, ['pointer64', ['void']]],
                    'Heap': [0x60, ['pointer64', ['void']]],
                }],
                '_HEAP_LARGE_ALLOC_DATA': [0x28, {
                    'TreeNode': [0x0, ['_RTL_BALANCED_NODE']],
                    'VirtualAddress': [0x18, ['unsigned long long']],
                    'UnusedBytes': [0x18,
                                    ['BitField', dict(start_bit=0, end_bit=16, native_type='unsigned long long')]],
                    'ExtraPresent': [0x20,
                                     ['BitField', dict(start_bit=0, end_bit=1, native_type='unsigned long long')]],
                    'Spare': [0x20, ['BitField', dict(start_bit=1, end_bit=12, native_type='unsigned long long')]],
                    'AllocatedPages': [0x20,
                                       ['BitField', dict(start_bit=12, end_bit=64, native_type='unsigned long long')]],
                }]
            })
        if self._config.profile == 'Win10x64_15063' or self._config.profile == 'Win10x64_14393':
            self.addr_space.profile.add_types({
                '_SEGMENT_HEAP': [0x5f0, {
                    'TotalReservedPages': [0x0, ['unsigned long long']],
                    'TotalCommittedPages': [0x8, ['unsigned long long']],
                    'Signature': [0x10, ['unsigned long']],
                    'GlobalFlags': [0x14, ['unsigned long']],
                    'FreeCommittedPages': [0x18, ['unsigned long long']],
                    'Interceptor': [0x20, ['unsigned long']],
                    'ProcessHeapListIndex': [0x24, ['unsigned short']],
                    'GlobalLockCount': [0x26, ['unsigned short']],
                    'GlobalLockOwner': [0x28, ['unsigned long']],
                    'LargeMetadataLock': [0x30, ['_RTL_SRWLOCK']],
                    'LargeAllocMetadata': [0x38, ['_RTL_RB_TREE']],
                    'LargeReservedPages': [0x48, ['unsigned long long']],
                    'LargeCommittedPages': [0x50, ['unsigned long long']],
                    'SegmentAllocatorLock': [0x58, ['_RTL_SRWLOCK']],
                    'SegmentListHead': [0x60, ['_LIST_ENTRY']],
                    'SegmentCount': [0x70, ['unsigned long long']],
                    'FreePageRanges': [0x78, ['_RTL_RB_TREE']],
                    'StackTraceInitVar': [0x88, ['_RTL_RUN_ONCE']],
                    'ContextExtendLock': [0x90, ['_RTL_SRWLOCK']],
                    'AllocatedBase': [0x98, ['pointer64', ['unsigned char']]],
                    'UncommittedBase': [0xa0, ['pointer64', ['unsigned char']]],
                    'ReservedLimit': [0xa8, ['pointer64', ['unsigned char']]],
                    'VsContext': [0xb0, ['_HEAP_VS_CONTEXT']],
                    'LfhContext': [0x120, ['_HEAP_LFH_CONTEXT']],
                }],
                '_HEAP_LARGE_ALLOC_DATA': [0x28, {
                    'TreeNode': [0x0, ['_RTL_BALANCED_NODE']],
                    'VirtualAddress': [0x18, ['unsigned long long']],
                    'UnusedBytes': [0x18,
                                    ['BitField', dict(start_bit=0, end_bit=16, native_type='unsigned long long')]],
                    'ExtraPresent': [0x20,
                                     ['BitField', dict(start_bit=0, end_bit=1, native_type='unsigned long long')]],
                    'Spare': [0x20, ['BitField', dict(start_bit=1, end_bit=12, native_type='unsigned long long')]],
                    'AllocatedPages': [0x20,
                                       ['BitField', dict(start_bit=12, end_bit=64, native_type='unsigned long long')]],
                }]
            })

    def filter_tasks(self, tasks):
        '''Filter the process'''
        if self._config.PID is None:
            return tasks

        try:
            pidlist = [int(p) for p in self._config.PID.split(',')]
        except ValueError:
            debug.error("Invalid PID {0}".format(self._config.PID))

        return [t for t in tasks if t.UniqueProcessId in pidlist]


    def calculate(self):
        #check wow64 process
        self.wow64 = False

        self.tasks = list(vtasks.pslist(self.addr_space))
        tasks_list = self.filter_tasks(vtasks.pslist(self.addr_space))

        #get handles for all processes
        self.segments = self.get_section_segments()


        #Check profile
        support_profiles = ['Win10x64_14393', 'Win10x64_15063',
                            'Win10x64_16299', 'Win10x64_17134',
                            'Win10x64_18362', 'Win10x64_17763',
                            'Win10x64_19041']
        profile = self._config.profile
        if not profile in support_profiles:
            debug.warning("Warning - {0} profile not supported".format(self._config.profile))


        #analyze through each process
        for task in tasks_list:
            if task.IsWow64:
                self.wow64 = True
            for data in self.analyze(task):
                yield data



    def analyze(self, task):
        """Analyze the userspace memory and return allocation information"""
        pid = task.UniqueProcessId
        #get the process address space
        ps_ad = task.get_process_address_space()
        user_pages = self.get_user_pages(ps_ad)

        #get the user allocations
        self.user_allocs = {}
        self.unreferenced = []
        self.get_user_allocations(task, user_pages)

        #get the unreferenced KSHARED_USER_DATA
        self.get_kshared()

        #process kernel metadata
        self.get_kernel_metadata()

        #process user space metadata
        self.get_user_metadata(ps_ad, task, pid)

        #sort addresses for output purposes
        addresses = self.user_allocs.keys()
        addresses.sort()

        #return user allocation information
        yield task, self.user_allocs, addresses, self.unreferenced


    def render_text(self, outfd, data):
        """Print the results to the screen"""
        outfd.write("Acquiring Section Handles\n")        
        for task, user_allocs, addresses, unreferenced in data:
            #output process info
            info = "Analysing PID: {0:d} - {1:s}\n"
            pid = task.UniqueProcessId 
            outfd.write(info.format(pid, task.ImageFileName))

            #output user allocation information
            outfd.write("User Allocations\n")
            header = "{0:12} {1:12}  {2:8} {3:8}  {4:17}  {5:13}  {6}\n"
            outfd.write(header.format("Start", "End", "Used", "Size", "Permission", "Type", "Description"))
            outfd.write(("-"*12 + " ") * 2 + " " +("-"*8 + " ") * 2 + " " + "-"*17 + " "*2 + "-"*13 + " "*2 + "-"*29 +
                        "\n")
            line = "{0:012x} {1:012x}  {2:08x} {3:08x}  {4:17s}  {5:14s} {6:s}"
            section = " "*80 + "{0}\n"
            for addr in addresses:
                alloc = user_allocs[addr]
                description = alloc.description()
                if description == "":
                    #output section info on same line
                    description = alloc.section_description
                    section_description = ""
                else:
                    #output section info on a different line
                    section_description = alloc.section_description
                outfd.write(line.format(alloc.start_address,
                                        alloc.end_address,
                                        alloc.allocated,
                                        alloc.size,
                                        alloc.permissions,
                                        alloc.type,
                                        description + "\n"))

                if description != "" and section_description != "":
                    outfd.write(section.format(alloc.section_description))
            outfd.write("\n")

            #output any unreferenced pages
            outfd.write("Unreferenced Pages\n")
            outfd.write("Start\t Size\n")   
            for start, size in unreferenced:
                outfd.write("{0:08x} {1:08x}\n".format(start, size))
            outfd.write("\n")


    def render_json(self, outfd, data):
        """Return the results as json output"""

        out=dict(plugin_name="userspace",
                         tool_name="volatility",
                         tool_version=constants.VERSION)
        

        for task, user_allocs, addresses, unreferenced in data:
            process = {}
            process["pid"]={"value":str(task.UniqueProcessId)}
            process["name"]={"value":str(task.ImageFileName)}
            out["process"] = process
            out["user_allocations"] = []
            for addr in addresses:
                alloc = user_allocs[addr]
                entry = {}
                entry['start'] = {"value":"{0:08x}".format(alloc.start_address)}
                entry['end'] = {"value":"{0:08x}".format(alloc.end_address)}
                entry['allocated'] = {"value":"{0:08x}".format(alloc.allocated)}
                entry['size'] = {"value":"{0:08x}".format(alloc.size)}
                entry['permissions'] = {"value":str(alloc.permissions)}
                entry['type'] = {"value":str(alloc.type)}
                entry['description'] = {"value":str(alloc.description())}
                entry['section'] = {"value":str(alloc.section_description)}
                out["user_allocations"].append(entry)
            out["unreferenced"] = []
            for start, size in unreferenced:
                unref = {}
                unref['start'] = {"value":str(start)}
                unref['size'] = {"value":str(size)}
                out["unreferenced"].append(unref)

            outfd.write(json.dumps(out,indent=4))

    def get_handles(self):
        for task in self.tasks:
            pid = task.UniqueProcessId
            if task.ObjectTable.HandleTableList:
                for handle in task.ObjectTable.handles():
                    if not handle.is_valid():
                        continue
                    name = ""
                    object_type = handle.get_object_type()
                    if handle.NameInfo.Name == None:
                        name = ''
                    else:
                        name = str(handle.NameInfo.Name)
                    yield pid, handle, object_type, name


    def get_section_segments(self):
        """Parse the object manager for segments of section objects"""
        segments = {}
        obj_handles = self.get_handles()
        for pid, h, otype, name in obj_handles:
            if otype == "Section":
                section_obj = h.dereference_as("_SECTION")
                segment_addr = section_obj.u1.ControlArea.Segment.v()
                segment = obj.Object("_SEGMENT", segment_addr, h.obj_vm)
                segments[segment_addr] = [pid, name, segment]
        return segments


    def get_user_pages(self, ps_ad):
        """Return a list of all accessible userspace virtual address pages"""
        all_pages = ps_ad.get_available_pages()
        pages = []
        if self.wow64:
            for page in all_pages:
                if page[0] < 0x80000000:
                    # not always a valid assumption (eg 3GB switch)
                    pages.append(page)
            return pages
        else:
            for page in all_pages:
                if page[0] < 0x800000000000:
                    pages.append(page)
            return pages


    def get_user_allocations(self, task, user_pages):
        """Traverse the VAD and get the user allocations and locate
            any unreferenced memory pages"""
        for vad in task.VadRoot.traverse():
            alloc = Userspace.UserAlloc(vad)
            user_pages = alloc.pages_allocated(user_pages)
            self.user_allocs[alloc.start_address] = alloc
        self.unreferenced = user_pages


    def get_kshared(self):
        """Find the _KSHARED_USER_DATA structure @ 7FFE0000"""
        pages = []
        if self.wow64:
            for [start, size] in self.unreferenced:
                if start == 0x7FFE0000:
                    alloc = Userspace.UserAlloc(None, start, size,
                                                "KSHARED_USER_DATA")
                    self.user_allocs[start] = alloc
                else:
                    pages.append([start, size])
            self.unreferenced = pages
        else:
            for [start, size] in self.unreferenced:
                if start == 0x7FFFFFFE0000:
                    alloc = Userspace.UserAlloc(None, start, size,
                                                "KSHARED_USER_DATA")
                    self.user_allocs[start] = alloc
                else:
                    pages.append([start, size])
            self.unreferenced = pages


    def get_kernel_metadata(self):
        """Get file object and section object metadata"""
        self.get_files()
        self.get_sections()


    def get_files(self):
        """Check each VAD for a file object"""
        for alloc in self.user_allocs.values():
            if alloc.vad:
                file_object = None
                try:
                    file_object = alloc.vad.FileObject
                except:
                    continue
                if file_object and file_object.is_valid():
                    filename = str(file_object.FileName)
                    if filename != "":
                        alloc.add_file(filename)
        

    def get_sections(self):
        """Link each section to a user allocation"""
        for alloc in self.user_allocs.values():
            if alloc.vad:
                control_area = None
                try:
                    mmvad = alloc.vad.dereference_as("_MMVAD")
                    control_area = mmvad.Subsection.ControlArea
                except:
                    pass
                if not control_area:
                    continue
                if not control_area.is_valid():
                    continue
                if control_area.v() != control_area.Segment.ControlArea.v():    
                    #invalid control area
                    continue
                #Control Area indicates the allocation is mapped
                alloc.type = "Shared"
                #check if the segment matches the segment from a section
                addr = control_area.Segment.v()
                if addr == 0:
                    continue
                if addr in self.segments:
                    pid, name, segment = self.segments[addr]
                    text = "Section - PID {0:05}, Name {1}".format(pid, name)
                    alloc.add_section(text)

        
    def get_user_metadata(self, ps_ad, task, pid):
        """Get the metadata from the userspace"""
        #Process Environment Block
        peb = task.Peb
        if not peb.is_valid():
            return
        try:
            for alloc in self.user_allocs.values():
                if alloc.start_address <= peb.v() <= alloc.end_address:
                    self.user_allocs[alloc.start_address].add_metadata("PEB",offset = hex(peb.v()))
                    break
        except:
            pass
        #Data from PEB
        gdi_handles, size = self.get_peb_data(peb)
        #Scan handle table for possible allocations
        if gdi_handles:
            self.get_gdi_data(ps_ad, gdi_handles, size, pid)
        #Heaps and related heap metadata
        self.get_heaps(ps_ad, peb)
        #Thread Environment Block and Stacks
        pcb = task.Pcb
        tebs = self.get_tebs(ps_ad, pcb)
        #Track the thread number
        count = 0
        for teb in tebs:
            self.get_stack(teb, count)
            count += 1
        count = 0
        #Check wow64 process
        if self.wow64:
            teb32s = self.get_teb32s(tebs, ps_ad)
            for teb32 in teb32s:
                self.get_wow64_stack(teb32, count)
                count += 1


    def get_peb_data(self, peb):
        """Get the metadata from the PEB"""
        fields = ["ProcessParameters", "AnsiCodePageData", "Ldr"
                  "SystemDefaultActivationContextData", "ActivationContextData",
                  "GdiSharedHandleTable", "pShimData", "pContextData",
                  "WerRegistrationData", "LeapSecondData", "ApiSetMap"]

        gdi = 0
        size = 0
        for field in fields:
            try:
                data = peb.m(field)
                addr = data.v()
                if addr == 0:
                    continue
                if not(addr in self.user_allocs):
                    #pointer is inside allocation rather than to start?
                    warning = "Pointer into allocation {0} @ {1:08x}"
                    debug.Warning(warning.format(field, addr))
                    continue
                #field specific information
                if field == "GdiSharedHandleTable":
                    #save for individual analysis
                    gdi = addr
                    size = self.user_allocs[addr].size
                elif field == "AnsiCodePageData":
                    #rename this field in output
                    field = "CodePage"
                elif field == "ProcessParameters":
                    #get the environment
                    environment = data.Environment.v()
                    self.user_allocs[environment].add_metadata("Environment")
                #add the metadata to the user alloc
                self.user_allocs[addr].add_metadata(field)
            except:
                continue
        return gdi, size


    def get_heaps(self, ps_ad, peb):
        """Get the heaps and heap related data structures"""
        num_heaps = peb.NumberOfHeaps.v()
        heap_count = 0
        if self.wow64:
            heaps = obj.Object('Array', offset=peb.ProcessHeaps.v(),
                               vm=ps_ad, targetType='unsigned long',
                               count=num_heaps)
        else:
            heaps = obj.Object('Array', offset = peb.ProcessHeaps.v(),
                                    vm = ps_ad, targetType = 'unsigned long long',
                                    count = num_heaps)
        heaps_list = list(heaps)

        #add shared heap to list
        heaps_list.append(peb.ReadOnlySharedMemoryBase)

        #get heap objects
        heap_objects = []
        for address in heaps_list:
            heap = obj.Object('_HEAP', offset=address.v(), vm=ps_ad)
            heap_objects.append([address,heap])

        #process each heap for metadata
        data = []
        for address,heap in heap_objects:
            if heap_count == len(heaps_list) - 1:
                #shared heap
                heap_info = str(heap_count) + " (Shared)"
            else:
                heap_info = str(heap_count)
            #add heap
            if not(heap.is_valid()):
                debug.warning("Unreadable heap @ ")
                heap_text = "Heap {0} (Unreadable)".format(heap_info)
                data.append([address.v(), heap_text])
                heap_count += 1
                continue
            is_nt_heap = False
            if heap.SegmentSignature == 0xffeeffee:
                data.append([address.v(), "Heap {0} NT Heap".format(heap_info)])
                is_nt_heap = True
            else:
                data.append([address.v(), "Heap {0} Segment Heap".format(heap_info)])
            if is_nt_heap:
                for virtual_alloc in self.get_heap_virtual_allocs(ps_ad, heap,
                                                                  heap_info):
                    data.append(virtual_alloc)
                #parse for heap segments
                for segment in self.get_heap_segments(ps_ad, heap, heap_info):
                    data.append(segment)
            else:
                for seg in self.get_seg_heap_seg(ps_ad, heap, heap_info):
                    data.append(seg)

                for large in self.get_seg_heap_large(ps_ad, heap, heap_info):
                    data.append(large)
            heap_count += 1
        #add heap data to user allocs
        for addr, text in data:
            try:
                self.user_allocs[addr].add_metadata(text)
            except:
                pass

    def get_seg_heap_seg(self, ps_ad, heap, heap_info):
        '''Get the backend allocation'''
        heap = obj.Object('_SEGMENT_HEAP', offset=heap.v(), vm=ps_ad)
        seg_count = 0
        seg_text = "Backend Alloc {0} of Segment Heap {1}"
        if self._config.profile == 'Win10x64_14393' or self._config.profile == 'Win10x64_15063':
            if heap.is_valid():
                start = heap.SegmentListHead.v()
                for offset in self.follow_list_entry(ps_ad, start, "Segment Heap Segment"):
                    yield [offset, seg_text.format(seg_count, heap_info)]
                    seg_count += 1
        else:
            segcontexts_list = list(heap.SegContexts)
            seg_contexts = []
            for seg in segcontexts_list:
                heap_seg = seg.dereference_as("_HEAP_SEG_CONTEXT")
                seg_contexts.append(heap_seg)
            for heap in seg_contexts:
                if heap.is_valid():
                    start = heap.SegmentListHead.v()
                    for offset in self.follow_list_entry(ps_ad, start, "Segment Heap Segment"):
                        yield [offset, seg_text.format(seg_count, heap_info)]
                        seg_count += 1


    def get_seg_heap_large(self, ps_ad, heap, heap_info):
        '''Get the large allocation'''
        heap = obj.Object('_SEGMENT_HEAP', offset=heap.v(), vm=ps_ad)
        seg_count = 0
        seg_text = "Large Block Alloc {0} of Segment Heap {1}"
        root = heap.LargeAllocMetadata.Root
        large_allocs = self.preorder(root)
        if large_allocs:
            for large in large_allocs:
                block = large.dereference_as("_HEAP_LARGE_ALLOC_DATA")
                yield [block.VirtualAddress, seg_text.format(seg_count, heap_info)]


    def preorder(self, root, res=[]):
        if not root:
            return
        res.append(root)
        self.preorder(root.Left, res)
        self.preorder(root.Right, res)
        return res


    def get_heap_virtual_allocs(self, ps_ad, heap, heap_info):
        """Get the heap virtual alloc entries of the heap"""
        #finding _HEAP_VIRTUAL_ALLOC objects
        va_count = 0
        start = heap.VirtualAllocdBlocks.v()
        va_text = "Virtual Alloc {0} of Heap {1}"
        for offset in self.follow_list_entry(ps_ad, start, "Virtual Alloc"):
            yield [offset, va_text.format(va_count, heap_info)]
            va_count += 1
        

    def follow_list_entry(self, ps_ad, offset, name):
        """Traverse a _LIST_ENTRY and yield all object offsets"""
        head = obj.Object('_LIST_ENTRY', offset=offset, vm=ps_ad)
        if not(head.is_valid()):
            warning = "Invalid {0} head @ {1:08x}"
            debug.warning(warning).format(name, head.v())
            return
        current = obj.Object('_LIST_ENTRY', offset=head.Flink.v(), vm=ps_ad)
        previous = head
        while current.v() != head.v():
            if current.Blink.v() != previous.v():
                #invalid
                warning = "Invalid flink"
                debug.warning(warning)
                return
            yield current.v()
            current = obj.Object('_LIST_ENTRY', offset=current.Flink.v(), 
                                                vm=ps_ad)
            previous = obj.Object('_LIST_ENTRY', offset=current.Blink.v(), 
                                                 vm=ps_ad)

    def get_heap_segments(self, ps_ad, heap, heap_info):
        """Get the segments of the heap"""
        for segment in self.get_heap_segments_list(ps_ad, heap, heap_info):
            yield segment

    def get_heap_segments_list(self, ps_ad, heap, heap_info):
        """Get the heap segments from _HEAP.SegmentListEntry"""
        seg_count = 0
        seg_text = "Segment {0} of Heap {1}"
        start = heap.SegmentListEntry.v()
        field_offset = ps_ad.profile.get_obj_offset("_HEAP_SEGMENT",
                                                    "SegmentListEntry")
        seg_text = "Segment {0} of Heap {1}"
        for offset in self.follow_list_entry(ps_ad, start, "Heap Segment"):
            #ignore internal segments, which will be in the original heap
            if (offset - field_offset) % 0x1000 == 0:
                text = seg_text.format(seg_count, heap_info)
                yield [offset - field_offset, text]
            seg_count += 1

    def get_gdi_data(self, ps_ad, gdi_handles, size, pid):
        """Look any allocations containing GDI objects by parsing
            gdi handle table"""
        #Parsing GDIHandleEntry objects
        #see http://msdn.microsoft.com/en-au/magazine/cc188782.aspx
        pointers = []
        current = gdi_handles + 0x4
        while current < gdi_handles + size:
            if ps_ad.is_valid_address(current):
                #read PID
                gdi_pid = ps_ad.read(current, 2)
                gdi_pid = struct.unpack("<H", gdi_pid)[0]                    
                if gdi_pid != pid:
                    current += 0x10
                    continue
                current += 0x8
                #read object address
                value = ps_ad.read(current, 4)
                value = struct.unpack("<L", value)[0]
                if value >= 0:
                    pointers.append(value)
                current += 0x8
            else:
                current += 0x1000
        #check if these objects are in user allocations    
        for pointer in pointers:
            for alloc in self.user_allocs.values():
                if alloc.start_address <= pointer < alloc.end_address:
                    alloc.add_gdi("(GDI Data)")


    def get_tebs(self, ps_ad, pcb):
        """Get the Thread Execution Blocks of the process"""
        tebs = []
        count = 0
        teb32s = []

        #get offset of ThreadListEntry, should be 0x1b0 on XP and 0x1e0 on Win7
        field_offset = ps_ad.profile.get_obj_offset("_KTHREAD", "ThreadListEntry")

        #get the threads
        for offset in self.follow_list_entry(ps_ad, pcb.ThreadListHead.v(), "Thread"):
            kthread = obj.Object('_KTHREAD', offset = offset - field_offset,
                                             vm = ps_ad)
            teb = kthread.Teb.dereference_as("_TEB")
            teb_addr = kthread.Teb.v()
            tebs.append(teb)

            try:
                for alloc in self.user_allocs.values():
                    if alloc.start_address <= teb.v() <= alloc.end_address:
                        self.user_allocs[alloc.start_address].add_metadata("TEB",offset = hex(teb.v()))
            except:
                pass
            count += 1

        return tebs

    def get_teb32s(self, tebs, ps_ad):
        """Get the Thread Execution Blocks of the wow64 process"""
        teb32s = []
        for teb in tebs:
            teb32 = obj.Object('_TEB32', offset=teb.v() + 0x2000,
                               vm=ps_ad)
            teb32s.append(teb32)

            try:
                for alloc in self.user_allocs.values():
                    if alloc.start_address <= teb32.v() <= alloc.end_address:
                        self.user_allocs[alloc.start_address].add_metadata("TEB32",offset = hex(teb32.v()))
            except:
                pass
        return teb32s

    def get_stack(self, teb, count):
        """Get the stack of the thread"""
        #check for TEBs that have been paged out
        #although this seems illogical, it can happen
        if not(teb.is_valid()):
            return
        stack_max = teb.DeallocationStack.v()
        text = "Stack of Thread {0}".format(count)
        try:
            self.user_allocs[stack_max].add_metadata(text)
        except:
            pass


    def get_wow64_stack(self, teb32, count):
        """Get the wow64 stack of the thread"""
        if not(teb32.is_valid()):
            return
        stack_max = teb32.DeallocationStack.v()
        text = "Wow64 Stack of Thread {0}".format(count)
        try:
            self.user_allocs[stack_max].add_metadata(text)
        except:
            pass

    class UserAlloc(object):
        """Class to describe a user allocation"""

        def __init__(self, vad, start_address=None, size=None, description=None):
            if vad:
                #For user allocations with a VAD (most allocations)
                self.vad = vad
                self.start_address = vad.Start
                self.end_address = vad.End
                self.permissions = self.get_permissions(vad)
                self.size = self.end_address - self.start_address + 1
                self.internal_description = ""
                self.section_description = ""
                tag = vad.Tag
                self.allocated = 0
                if tag == "Vad ":
                    #This type of VAD is always mapped
                    self.type = "VMapped"
                else:
                    self.type = "Private      "
            else:
                #For allocations without a VAD, eg KSHARED_USER_DATA
                self.vad = None
                self.start_address = start_address
                self.end_address = start_address + size - 1
                self.internal_description = description
                self.size = size
                #set allocated manually since it is described by the VAD
                #and it must be this size else it would have not been located
                self.allocated = size
                self.type = "N/A"
                self.permissions = "N/A"     
            self.section_description = ""
            self.gdi_description = ""

        def description(self):
            """Return a string that describes this allocation"""
            description = self.internal_description
            if self.gdi_description != "":
                description += " " + self.gdi_description
            description = description.strip()
            return description


        def get_permissions(self, vad):
            """Get the permissions of this user allocation"""
            permissions = vad.VadFlags.Protection.v()
            try:
                permissions = vadinfo.PROTECT_FLAGS[permissions]
                #remove unnecessary text to compress output
                permissions = permissions.replace("PAGE_", "")
                return permissions
            except IndexError:
                return "Unknown - {0:x}".format(permissions)


        def pages_allocated(self, user_pages):
           """Determine how much of an allocation is actually accessible"""
           # operates on individual page information (not ranges)
           # returns unused pages separately to speed future searches
           allocated = 0
           unused = []
           for start, size in user_pages:
               if start >= self.start_address and start <= self.end_address:
                   allocated += size
               else:
                   unused.append([start,size])
           self.allocated = allocated       
           return unused            


        def add_section(self, text):
            """Add section metadata separately, as a user allocation 
            can potentially have section and content info (eg shared heap)"""
            self.section_description = text


        def add_file(self, text):
            """Add file information"""
            self.add_metadata(text)


        def add_metadata(self, text, offset = ''):
            """Add information about the contents of this user allocation"""
            self.internal_description += text +str(offset) + ' '


        def add_gdi(self, text):
            """GDI objects found in this user allocation"""
            self.gdi_description = text

