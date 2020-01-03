#!/usr/bin/env python
# Copyright (c) 2020 Matt Borgerson
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""
Python 3 Library to work with `.xbe` files, the executable file format for the
original Xbox game console.
"""
import ctypes
import logging

log = logging.getLogger(__name__)

class XbeKernelImage:
	exports = {
		1:   'AvGetSavedDataAddress',
		2:   'AvSendTVEncoderOption',
		3:   'AvSetDisplayMode',
		4:   'AvSetSavedDataAddress',
		5:   'DbgBreakPoint',
		6:   'DbgBreakPointWithStatus',
		7:   'DbgLoadImageSymbols',
		8:   'DbgPrint',
		9:   'HalReadSMCTrayState',
		10:  'DbgPrompt',
		11:  'DbgUnLoadImageSymbols',
		12:  'ExAcquireReadWriteLockExclusive',
		13:  'ExAcquireReadWriteLockShared',
		14:  'ExAllocatePool',
		15:  'ExAllocatePoolWithTag',
		16:  'ExEventObjectType',
		17:  'ExFreePool',
		18:  'ExInitializeReadWriteLock',
		19:  'ExInterlockedAddLargeInteger',
		20:  'ExInterlockedAddLargeStatistic',
		21:  'ExInterlockedCompareExchange64',
		22:  'ExMutantObjectType',
		23:  'ExQueryPoolBlockSize',
		24:  'ExQueryNonVolatileSetting',
		25:  'ExReadWriteRefurbInfo',
		26:  'ExRaiseException',
		27:  'ExRaiseStatus',
		28:  'ExReleaseReadWriteLock',
		29:  'ExSaveNonVolatileSetting',
		30:  'ExSemaphoreObjectType',
		31:  'ExTimerObjectType',
		32:  'ExfInterlockedInsertHeadList',
		33:  'ExfInterlockedInsertTailList',
		34:  'ExfInterlockedRemoveHeadList',
		35:  'FscGetCacheSize',
		36:  'FscInvalidateIdleBlocks',
		37:  'FscSetCacheSize',
		38:  'HalClearSoftwareInterrupt',
		39:  'HalDisableSystemInterrupt',
		40:  'HalDiskCachePartitionCount',
		41:  'HalDiskModelNumber',
		42:  'HalDiskSerialNumber',
		43:  'HalEnableSystemInterrupt',
		44:  'HalGetInterruptVector',
		45:  'HalReadSMBusValue',
		46:  'HalReadWritePCISpace',
		47:  'HalRegisterShutdownNotification',
		48:  'HalRequestSoftwareInterrupt',
		49:  'HalReturnToFirmware',
		50:  'HalWriteSMBusValue',
		51:  'InterlockedCompareExchange',
		52:  'InterlockedDecrement',
		53:  'InterlockedIncrement',
		54:  'InterlockedExchange',
		55:  'InterlockedExchangeAdd',
		56:  'InterlockedFlushSList',
		57:  'InterlockedPopEntrySList',
		58:  'InterlockedPushEntrySList',
		59:  'IoAllocateIrp',
		60:  'IoBuildAsynchronousFsdRequest',
		61:  'IoBuildDeviceIoControlRequest',
		62:  'IoBuildSynchronousFsdRequest',
		63:  'IoCheckShareAccess',
		64:  'IoCompletionObjectType',
		65:  'IoCreateDevice',
		66:  'IoCreateFile',
		67:  'IoCreateSymbolicLink',
		68:  'IoDeleteDevice',
		69:  'IoDeleteSymbolicLink',
		70:  'IoDeviceObjectType',
		71:  'IoFileObjectType',
		72:  'IoFreeIrp',
		73:  'IoInitializeIrp',
		74:  'IoInvalidDeviceRequest',
		75:  'IoQueryFileInformation',
		76:  'IoQueryVolumeInformation',
		77:  'IoQueueThreadIrp',
		78:  'IoRemoveShareAccess',
		79:  'IoSetIoCompletion',
		80:  'IoSetShareAccess',
		81:  'IoStartNextPacket',
		82:  'IoStartNextPacketByKey',
		83:  'IoStartPacket',
		84:  'IoSynchronousDeviceIoControlRequest',
		85:  'IoSynchronousFsdRequest',
		86:  'IofCallDriver',
		87:  'IofCompleteRequest',
		88:  'KdDebuggerEnabled',
		89:  'KdDebuggerNotPresent',
		90:  'IoDismountVolume',
		91:  'IoDismountVolumeByName',
		92:  'KeAlertResumeThread',
		93:  'KeAlertThread',
		94:  'KeBoostPriorityThread',
		95:  'KeBugCheck',
		96:  'KeBugCheckEx',
		97:  'KeCancelTimer',
		98:  'KeConnectInterrupt',
		99:  'KeDelayExecutionThread',
		100: 'KeDisconnectInterrupt',
		101: 'KeEnterCriticalRegion',
		102: 'MmGlobalData',
		103: 'KeGetCurrentIrql',
		104: 'KeGetCurrentThread',
		105: 'KeInitializeApc',
		106: 'KeInitializeDeviceQueue',
		107: 'KeInitializeDpc',
		108: 'KeInitializeEvent',
		109: 'KeInitializeInterrupt',
		110: 'KeInitializeMutant',
		111: 'KeInitializeQueue',
		112: 'KeInitializeSemaphore',
		113: 'KeInitializeTimerEx',
		114: 'KeInsertByKeyDeviceQueue',
		115: 'KeInsertDeviceQueue',
		116: 'KeInsertHeadQueue',
		117: 'KeInsertQueue',
		118: 'KeInsertQueueApc',
		119: 'KeInsertQueueDpc',
		120: 'KeInterruptTime',
		121: 'KeIsExecutingDpc',
		122: 'KeLeaveCriticalRegion',
		123: 'KePulseEvent',
		124: 'KeQueryBasePriorityThread',
		125: 'KeQueryInterruptTime',
		126: 'KeQueryPerformanceCounter',
		127: 'KeQueryPerformanceFrequency',
		128: 'KeQuerySystemTime',
		129: 'KeRaiseIrqlToDpcLevel',
		130: 'KeRaiseIrqlToSynchLevel',
		131: 'KeReleaseMutant',
		132: 'KeReleaseSemaphore',
		133: 'KeRemoveByKeyDeviceQueue',
		134: 'KeRemoveDeviceQueue',
		135: 'KeRemoveEntryDeviceQueue',
		136: 'KeRemoveQueue',
		137: 'KeRemoveQueueDpc',
		138: 'KeResetEvent',
		139: 'KeRestoreFloatingPointState',
		140: 'KeResumeThread',
		141: 'KeRundownQueue',
		142: 'KeSaveFloatingPointState',
		143: 'KeSetBasePriorityThread',
		144: 'KeSetDisableBoostThread',
		145: 'KeSetEvent',
		146: 'KeSetEventBoostPriority',
		147: 'KeSetPriorityProcess',
		148: 'KeSetPriorityThread',
		149: 'KeSetTimer',
		150: 'KeSetTimerEx',
		151: 'KeStallExecutionProcessor',
		152: 'KeSuspendThread',
		153: 'KeSynchronizeExecution',
		154: 'KeSystemTime',
		155: 'KeTestAlertThread',
		156: 'KeTickCount',
		157: 'KeTimeIncrement',
		158: 'KeWaitForMultipleObjects',
		159: 'KeWaitForSingleObject',
		160: 'KfRaiseIrql',
		161: 'KfLowerIrql',
		162: 'KiBugCheckData',
		163: 'KiUnlockDispatcherDatabase',
		164: 'LaunchDataPage',
		165: 'MmAllocateContiguousMemory',
		166: 'MmAllocateContiguousMemoryEx',
		167: 'MmAllocateSystemMemory',
		168: 'MmClaimGpuInstanceMemory',
		169: 'MmCreateKernelStack',
		170: 'MmDeleteKernelStack',
		171: 'MmFreeContiguousMemory',
		172: 'MmFreeSystemMemory',
		173: 'MmGetPhysicalAddress',
		174: 'MmIsAddressValid',
		175: 'MmLockUnlockBufferPages',
		176: 'MmLockUnlockPhysicalPage',
		177: 'MmMapIoSpace',
		178: 'MmPersistContiguousMemory',
		179: 'MmQueryAddressProtect',
		180: 'MmQueryAllocationSize',
		181: 'MmQueryStatistics',
		182: 'MmSetAddressProtect',
		183: 'MmUnmapIoSpace',
		184: 'NtAllocateVirtualMemory',
		185: 'NtCancelTimer',
		186: 'NtClearEvent',
		187: 'NtClose',
		188: 'NtCreateDirectoryObject',
		189: 'NtCreateEvent',
		190: 'NtCreateFile',
		191: 'NtCreateIoCompletion',
		192: 'NtCreateMutant',
		193: 'NtCreateSemaphore',
		194: 'NtCreateTimer',
		195: 'NtDeleteFile',
		196: 'NtDeviceIoControlFile',
		197: 'NtDuplicateObject',
		198: 'NtFlushBuffersFile',
		199: 'NtFreeVirtualMemory',
		200: 'NtFsControlFile',
		201: 'NtOpenDirectoryObject',
		202: 'NtOpenFile',
		203: 'NtOpenSymbolicLinkObject',
		204: 'NtProtectVirtualMemory',
		205: 'NtPulseEvent',
		206: 'NtQueueApcThread',
		207: 'NtQueryDirectoryFile',
		208: 'NtQueryDirectoryObject',
		209: 'NtQueryEvent',
		210: 'NtQueryFullAttributesFile',
		211: 'NtQueryInformationFile',
		212: 'NtQueryIoCompletion',
		213: 'NtQueryMutant',
		214: 'NtQuerySemaphore',
		215: 'NtQuerySymbolicLinkObject',
		216: 'NtQueryTimer',
		217: 'NtQueryVirtualMemory',
		218: 'NtQueryVolumeInformationFile',
		219: 'NtReadFile',
		220: 'NtReadFileScatter',
		221: 'NtReleaseMutant',
		222: 'NtReleaseSemaphore',
		223: 'NtRemoveIoCompletion',
		224: 'NtResumeThread',
		225: 'NtSetEvent',
		226: 'NtSetInformationFile',
		227: 'NtSetIoCompletion',
		228: 'NtSetSystemTime',
		229: 'NtSetTimerEx',
		230: 'NtSignalAndWaitForSingleObjectEx',
		231: 'NtSuspendThread',
		232: 'NtUserIoApcDispatcher',
		233: 'NtWaitForSingleObject',
		234: 'NtWaitForSingleObjectEx',
		235: 'NtWaitForMultipleObjectsEx',
		236: 'NtWriteFile',
		237: 'NtWriteFileGather',
		238: 'NtYieldExecution',
		239: 'ObCreateObject',
		240: 'ObDirectoryObjectType',
		241: 'ObInsertObject',
		242: 'ObMakeTemporaryObject',
		243: 'ObOpenObjectByName',
		244: 'ObOpenObjectByPointer',
		245: 'ObpObjectHandleTable',
		246: 'ObReferenceObjectByHandle',
		247: 'ObReferenceObjectByName',
		248: 'ObReferenceObjectByPointer',
		249: 'ObSymbolicLinkObjectType',
		250: 'ObfDereferenceObject',
		251: 'ObfReferenceObject',
		252: 'PhyGetLinkState',
		253: 'PhyInitialize',
		254: 'PsCreateSystemThread',
		255: 'PsCreateSystemThreadEx',
		256: 'PsQueryStatistics',
		257: 'PsSetCreateThreadNotifyRoutine',
		258: 'PsTerminateSystemThread',
		259: 'PsThreadObjectType',
		260: 'RtlAnsiStringToUnicodeString',
		261: 'RtlAppendStringToString',
		262: 'RtlAppendUnicodeStringToString',
		263: 'RtlAppendUnicodeToString',
		264: 'RtlAssert',
		265: 'RtlCaptureContext',
		266: 'RtlCaptureStackBackTrace',
		267: 'RtlCharToInteger',
		268: 'RtlCompareMemory',
		269: 'RtlCompareMemoryUlong',
		270: 'RtlCompareString',
		271: 'RtlCompareUnicodeString',
		272: 'RtlCopyString',
		273: 'RtlCopyUnicodeString',
		274: 'RtlCreateUnicodeString',
		275: 'RtlDowncaseUnicodeChar',
		276: 'RtlDowncaseUnicodeString',
		277: 'RtlEnterCriticalSection',
		278: 'RtlEnterCriticalSectionAndRegion',
		279: 'RtlEqualString',
		280: 'RtlEqualUnicodeString',
		281: 'RtlExtendedIntegerMultiply',
		282: 'RtlExtendedLargeIntegerDivide',
		283: 'RtlExtendedMagicDivide',
		284: 'RtlFillMemory',
		285: 'RtlFillMemoryUlong',
		286: 'RtlFreeAnsiString',
		287: 'RtlFreeUnicodeString',
		288: 'RtlGetCallersAddress',
		289: 'RtlInitAnsiString',
		290: 'RtlInitUnicodeString',
		291: 'RtlInitializeCriticalSection',
		292: 'RtlIntegerToChar',
		293: 'RtlIntegerToUnicodeString',
		294: 'RtlLeaveCriticalSection',
		295: 'RtlLeaveCriticalSectionAndRegion',
		296: 'RtlLowerChar',
		297: 'RtlMapGenericMask',
		298: 'RtlMoveMemory',
		299: 'RtlMultiByteToUnicodeN',
		300: 'RtlMultiByteToUnicodeSize',
		301: 'RtlNtStatusToDosError',
		302: 'RtlRaiseException',
		303: 'RtlRaiseStatus',
		304: 'RtlTimeFieldsToTime',
		305: 'RtlTimeToTimeFields',
		306: 'RtlTryEnterCriticalSection',
		307: 'RtlUlongByteSwap',
		308: 'RtlUnicodeStringToAnsiString',
		309: 'RtlUnicodeStringToInteger',
		310: 'RtlUnicodeToMultiByteN',
		311: 'RtlUnicodeToMultiByteSize',
		312: 'RtlUnwind',
		313: 'RtlUpcaseUnicodeChar',
		314: 'RtlUpcaseUnicodeString',
		315: 'RtlUpcaseUnicodeToMultiByteN',
		316: 'RtlUpperChar',
		317: 'RtlUpperString',
		318: 'RtlUshortByteSwap',
		319: 'RtlWalkFrameChain',
		320: 'RtlZeroMemory',
		321: 'XboxEEPROMKey',
		322: 'XboxHardwareInfo',
		323: 'XboxHDKey',
		324: 'XboxKrnlVersion',
		325: 'XboxSignatureKey',
		326: 'XeImageFileName',
		327: 'XeLoadSection',
		328: 'XeUnloadSection',
		329: 'READ_PORT_BUFFER_UCHAR',
		330: 'READ_PORT_BUFFER_USHORT',
		331: 'READ_PORT_BUFFER_ULONG',
		332: 'WRITE_PORT_BUFFER_UCHAR',
		333: 'WRITE_PORT_BUFFER_USHORT',
		334: 'WRITE_PORT_BUFFER_ULONG',
		335: 'XcSHAInit',
		336: 'XcSHAUpdate',
		337: 'XcSHAFinal',
		338: 'XcRC4Key',
		339: 'XcRC4Crypt',
		340: 'XcHMAC',
		341: 'XcPKEncPublic',
		342: 'XcPKDecPrivate',
		343: 'XcPKGetKeyLen',
		344: 'XcVerifyPKCS1Signature',
		345: 'XcModExp',
		346: 'XcDESKeyParity',
		347: 'XcKeyTable',
		348: 'XcBlockCrypt',
		349: 'XcBlockCryptCBC',
		350: 'XcCryptService',
		351: 'XcUpdateCrypto',
		352: 'RtlRip',
		353: 'XboxLANKey',
		354: 'XboxAlternateSignatureKeys',
		355: 'XePublicKeyData',
		356: 'HalBootSMCVideoMode',
		357: 'IdexChannelObject',
		358: 'HalIsResetOrShutdownPending',
		359: 'IoMarkIrpMustComplete',
		360: 'HalInitiateShutdown',
		361: 'RtlSnprintf',
		362: 'RtlSprintf',
		363: 'RtlVsnprintf',
		364: 'RtlVsprintf',
		365: 'HalEnableSecureTrayEject',
		366: 'HalWriteSMCScratchRegister',
		374: 'MmDbgAllocateMemory',
		375: 'MmDbgFreeMemory',
		376: 'MmDbgQueryAvailablePages',
		377: 'MmDbgReleaseAddress',
		378: 'MmDbgWriteCheck',
		}

class StructurePrintMixin:
	"""A simple mixin to __repr__ ctypes structures"""
	def __repr__(self):
		return self.dumps()

	def dumps(self, indent=0):
		"""Pretty-print all fields and values of the structure, return a string"""
		s = ''
		max_name_len = max(map(len, [name for name, _ in self._fields_]))
		for fname, ftype in self._fields_:
			s += ' ' * indent + ('%s: ' % fname).ljust(max_name_len + 2)
			if ftype in [ctypes.c_uint8, ctypes.c_uint16, ctypes.c_uint32]:
			    s += '0x%x' % getattr(self, fname)
			elif issubclass(ftype, ctypes.Array) and ftype._type_ in  [ctypes.c_uint8, ctypes.c_uint16, ctypes.c_uint32]:
				if ftype._type_ is ctypes.c_uint8:
					fmt, wrap = '%02x ', 16
				elif ftype._type_ is ctypes.c_uint16:
					fmt, wrap = '%04x ', 8
				elif ftype._type_ is ctypes.c_uint32:
					fmt, wrap = '%08x ', 4
				else:
					assert(0)

				for i in range(ftype._length_):
					if i % wrap == 0:
						s += '\n' + ' ' * (indent + 2)
					s += fmt % getattr(self, fname)[i]
			else:
				s += '?'

			s += '\n'
		return s.rstrip() # Trim trailing newline

class XbeImageHeader(ctypes.LittleEndianStructure, StructurePrintMixin):
	FLAG_MOUNT_UTILITY_DRIVE  = 0x00000001
	FLAG_FORMAT_UTILITY_DRIVE = 0x00000002
	FLAG_LIMIT64MB            = 0x00000004
	FLAG_DONT_SETUP_HARDDISK  = 0x00000008

	_pack_ = 1
	_fields_ = [
		('magic',                       ctypes.c_uint32),
		('signature',                   ctypes.c_uint8 * 256),
		('base_addr',                   ctypes.c_uint32),
		('headers_size',                ctypes.c_uint32),
		('image_size',                  ctypes.c_uint32),
		('image_header_size',           ctypes.c_uint32),
		('timestamp',                   ctypes.c_uint32),
		('certificate_addr',            ctypes.c_uint32),
		('section_count',               ctypes.c_uint32),
		('section_headers_addr',        ctypes.c_uint32),
		('init_flags',                  ctypes.c_uint32),
		('entry_addr',                  ctypes.c_uint32),
		('tls_addr',                    ctypes.c_uint32),
		('pe_stack_commit',             ctypes.c_uint32),
		('pe_heap_reserve',             ctypes.c_uint32),
		('pe_heap_commit',              ctypes.c_uint32),
		('pe_base_addr',                ctypes.c_uint32),
		('pe_image_size',               ctypes.c_uint32),
		('pe_checksum',                 ctypes.c_uint32),
		('pe_timestamp',                ctypes.c_uint32),
		('debug_pathname_addr',         ctypes.c_uint32),
		('debug_filename_addr',         ctypes.c_uint32),
		('debug_unicode_filename_addr', ctypes.c_uint32),
		('kern_thunk_addr',             ctypes.c_uint32),
		('import_dir_addr',             ctypes.c_uint32),
		('lib_versions_count',          ctypes.c_uint32),
		('lib_versions_addr',           ctypes.c_uint32),
		('kern_lib_version_addr',       ctypes.c_uint32),
		('xapi_lib_version_addr',       ctypes.c_uint32),
		('logo_addr',                   ctypes.c_uint32),
		('logo_size',                   ctypes.c_uint32),
		]

class XbeImageCertificate(ctypes.LittleEndianStructure, StructurePrintMixin):
	FLAG_MEDIA_TYPE_HARD_DISK           = 0x00000001
	FLAG_MEDIA_TYPE_DVD_X2              = 0x00000002
	FLAG_MEDIA_TYPE_DVD_CD              = 0x00000004
	FLAG_MEDIA_TYPE_CD                  = 0x00000008
	FLAG_MEDIA_TYPE_DVD_5_RO            = 0x00000010
	FLAG_MEDIA_TYPE_DVD_9_RO            = 0x00000020
	FLAG_MEDIA_TYPE_DVD_5_RW            = 0x00000040
	FLAG_MEDIA_TYPE_DVD_9_RW            = 0x00000080
	FLAG_MEDIA_TYPE_DONGLE              = 0x00000100
	FLAG_MEDIA_TYPE_MEDIA_BOARD         = 0x00000200
	FLAG_MEDIA_TYPE_NONSECURE_HARD_DISK = 0x40000000
	FLAG_MEDIA_TYPE_NONSECURE_MODE      = 0x80000000
	FLAG_MEDIA_TYPE_MEDIA_MASK          = 0x00FFFFFF
	FLAG_GAME_REGION_NA                 = 0x00000001
	FLAG_GAME_REGION_JAPAN              = 0x00000002
	FLAG_GAME_REGION_RESTOFWORLD        = 0x00000004
	FLAG_GAME_REGION_MANUFACTURING      = 0x80000000

	_pack_ = 1
	_fields_ = [
		('size',               ctypes.c_uint32),
		('timestamp',          ctypes.c_uint32),
		('title_id',           ctypes.c_uint32),
		('title_name',         ctypes.c_uint16 * 40),
		('title_alt_ids',      ctypes.c_uint32 * 16),
		('allowed_media',      ctypes.c_uint32),
		('region',             ctypes.c_uint32),
		('ratings',            ctypes.c_uint32),
		('disc_num',           ctypes.c_uint32),
		('version',            ctypes.c_uint32),
		('lan_key',            ctypes.c_uint8 * 16),
		('signature_key',      ctypes.c_uint8 * 16),
		('alt_signature_keys', (ctypes.c_uint8 * (16*16))),
		]

class XbeSectionHeader(ctypes.LittleEndianStructure, StructurePrintMixin):
	FLAG_WRITABLE            = 0X00000001
	FLAG_PRELOAD             = 0X00000002
	FLAG_EXECUTABLE          = 0X00000004
	FLAG_INSERTED_FILE       = 0X00000008
	FLAG_HEAD_PAGE_READ_ONLY = 0X00000010
	FLAG_TAIL_PAGE_READ_ONLY = 0X00000020

	_pack_ = 1
	_fields_ = [
		# FIXME: Add flag defs
		('flags',                           ctypes.c_uint32),
		('virtual_addr',                    ctypes.c_uint32),
		('virtual_size',                    ctypes.c_uint32),
		('raw_addr',                        ctypes.c_uint32),
		('raw_size',                        ctypes.c_uint32),
		('section_name_addr',               ctypes.c_uint32),
		('section_name_ref_count',          ctypes.c_uint32),
		('head_shared_page_ref_count_addr', ctypes.c_uint32),
		('tail_shared_page_ref_count_addr', ctypes.c_uint32),
		('digest',                          ctypes.c_uint8 * 20),
		]

class XbeLibraryVersion(ctypes.LittleEndianStructure, StructurePrintMixin):
	FLAG_QFEVERSION  = 0x1FFF # (13-Bit Mask)
	FLAG_APPROVED    = 0x6000 # (02-Bit Mask)
	FLAG_DEBUG_BUILD = 0x8000 # (01-Bit Mask)

	_pack_ = 1
	_fields_ = [
		('name',      ctypes.c_char * 8),
		('ver_major', ctypes.c_uint16),
		('ver_minor', ctypes.c_uint16),
		('ver_build', ctypes.c_uint16),
		('flags',     ctypes.c_uint16),
		]

class XbeTlsHeader(ctypes.LittleEndianStructure, StructurePrintMixin):
	_pack_ = 1
	_fields_ = [
		('data_start_addr',   ctypes.c_uint32),
		('data_end_addr',     ctypes.c_uint32),
		('tls_index_addr',    ctypes.c_uint32),
		('tls_callback_addr', ctypes.c_uint32),
		('zero_fill_size',    ctypes.c_uint32),
		('characteristics',   ctypes.c_uint32),
		]

class Xbe:
	ENTRY_DEBUG   = 0x94859D4B
	ENTRY_RETAIL  = 0xA8FC57AB
	KTHUNK_DEBUG  = 0xEFB1F152
	KTHUNK_RETAIL = 0x5B6D40B6

	def __init__(self, data=None):
		"""Constructor"""
		# Parse XBE header
		log.debug('Parsing image header at offset 0')
		self.header = XbeImageHeader.from_buffer_copy(data, 0)
		# FIXME: Validate magic
		# FIXME: Validate signature/integrity
		log.debug('Image Header:\n' + self.header.dumps(indent=2))

		self.header_data = data[0:self.header.image_header_size]

		# Unscramble entry address
		self.entry_addr = self.header.entry_addr ^ Xbe.ENTRY_DEBUG
		if self.entry_addr < 0x4000000:
			self.is_debug = True
		else:
			self.entry_addr = self.header.entry_addr ^ Xbe.ENTRY_RETAIL
			self.is_debug = False
		log.debug('XBE Entry Address: 0x%x' % self.entry_addr)
		log.debug('XBE is ' + ('Debug' if self.is_debug else 'Retail') + ' build')

		# Parse sections
		self.sections = {}
		sec_hdr_offset = self.vaddr_to_file_offset(self.header.section_headers_addr)
		for i in range(self.header.section_count):
			# FIXME: Validate addresses

			# Load section header
			log.debug('Parsing section header at offset 0x%x' % sec_hdr_offset)
			sec_hdr = XbeSectionHeader.from_buffer_copy(data, sec_hdr_offset)

			# Get section name
			sec_name = self.get_cstring_from_offset(data, self.vaddr_to_file_offset(sec_hdr.section_name_addr))

			# Get section data
			sec_data_start = sec_hdr.raw_addr
			sec_data_end = sec_data_start + sec_hdr.raw_size
			sec_data = data[sec_data_start:sec_data_end]
			self.sections[sec_name] = XbeSection(sec_name, sec_hdr, sec_data)

			log.debug(('Section %d: %s\n' % (i, sec_name)) + sec_hdr.dumps(indent=2))
			sec_hdr_offset += ctypes.sizeof(XbeSectionHeader)

		# Parse kernel imports
		self.kern_imports = []
		# FIXME: Validate address
		kern_thunk_table_offset = self.header.kern_thunk_addr
		kern_thunk_table_offset ^= Xbe.KTHUNK_DEBUG if self.is_debug else Xbe.KTHUNK_RETAIL
		kern_thunk_table_offset = self.vaddr_to_file_offset(kern_thunk_table_offset)
		log.debug('Parsing kernel thunk table at offset 0x%x' % kern_thunk_table_offset)
		i = 0
		while True:
			x = ctypes.c_uint32.from_buffer_copy(data, kern_thunk_table_offset)
			if x.value == 0: break
			import_name = XbeKernelImage.exports[x.value-0x80000000]
			self.kern_imports.append(import_name)
			log.debug('Import %d: 0x%x - %s' % (i, x.value, import_name))
			i += 1
			kern_thunk_table_offset += 4

		# Load certificate
		cert_offset = self.vaddr_to_file_offset(self.header.certificate_addr)
		log.debug('Parsing image certificate at offset 0x%x' % cert_offset)
		# FIXME: Validate address
		self.cert = XbeImageCertificate.from_buffer_copy(data, cert_offset)
		self.title_name = str(self.cert.title_name, encoding='utf_16').rstrip('\x00')
		log.debug('XBE Title Name: ' + self.title_name)
		log.debug('XBE Title Id: ' + hex(self.cert.title_id))
		log.debug('Certificate:\n' + self.cert.dumps(indent=2))

		# Parse libraries
		self.libraries = {}
		lib_ver_offset = self.vaddr_to_file_offset(self.header.lib_versions_addr)
		log.debug('Parsing library versions at offset 0x%x' % lib_ver_offset)
		for i in range(self.header.lib_versions_count):
			# FIXME: Validate address
			lib_ver = XbeLibraryVersion.from_buffer_copy(data, lib_ver_offset)
			lib = XbeLibrary(lib_ver)
			self.libraries[lib.name] = lib
			log.debug('Library %d: \'%s\' (%d.%d.%d)' % (i, lib.name, lib.header.ver_major, lib.header.ver_minor, lib.header.ver_build))
			lib_ver_offset += ctypes.sizeof(XbeLibraryVersion)

		# Parse TLS
		tls_offset = self.vaddr_to_file_offset(self.header.tls_addr)
		log.debug('Parsing TLS header at offset 0x%x' % tls_offset)
		self.tls = XbeTlsHeader.from_buffer_copy(data, tls_offset)
		log.debug('TLS:\n' + self.tls.dumps(indent=2))

	def get_cstring_from_offset(self, data, offset):
		"""Read null-terminated string from `offset` in `data`"""
		name = bytearray()
		while True:
			x = data[offset]
			if x == 0: break
			name.append(x)
			offset += 1
		return str(name, encoding='ascii')

	def vaddr_to_file_offset(self, addr):
		"""Get XBE file offset from virtual address"""
		# FIXME: Does not take into account access length! Be wary of section boundaries.
		hdr_start = self.header.base_addr
		hdr_end = hdr_start + self.header.headers_size
		if hdr_start <= addr and addr < hdr_end:
			return addr - hdr_start

		for name, sec in self.sections.items():
			sec_start = sec.header.virtual_addr
			sec_end = sec_start + sec.header.virtual_size
			if sec_start <= addr and addr < sec_end:
				return (addr - sec_start) + sec.header.raw_addr

		raise IndexError('Could not map virtual address to XBE file offset')

	@classmethod
	def from_file(cls, path):
		"""Create Xbe object from file path"""
		with open(path, 'rb') as f:
			data = f.read()
			return cls(data)

	def __repr__(self):
		return '<Xbe name=\'%s\' title_id=0x%08x>' % (
			self.title_name,
			self.cert.title_id)

class XbeSection:
	def __init__(self, name, header, data):
		self.name = name
		self.header = header
		self.data = data

	def __repr__(self):
		return '<XbeSection name=\'%s\' vaddr=0x%x vsize=0x%x>' % (
			self.name,
			self.header.virtual_addr,
			self.header.virtual_size)

class XbeLibrary:
	def __init__(self, header):
		self.header = header
		self.name = str(self.header.name, encoding='ascii')

	def __repr__(self):
		return '<XbeLibrary \'%s\' (%d.%d.%d)>' % (
			self.name,
			self.header.ver_major,
			self.header.ver_minor,
			self.header.ver_build)
