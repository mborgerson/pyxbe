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
import struct
import time

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
		# FIXME: Doesn't work with inherited fields
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

class XbeImageHeaderExtended(XbeImageHeader):
	_pack_ = 1
	_fields_ = [
		('lib_features_addr',           ctypes.c_uint32),
		('lib_features_count',          ctypes.c_uint32),
		('debug_info',                  ctypes.c_uint32),
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

class XbeImageCertificateExtended(XbeImageCertificate):
	_fields_ = [
		('unknown',            ctypes.c_uint8 * 28), # FIXME
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

class XbeLibraryFeatureDescriptor(ctypes.LittleEndianStructure, StructurePrintMixin):
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
		self.header = XbeImageHeader()
		self.pathname = ''
		self.filename = ''
		self.filename_uc = self.filename
		self.entry_addr = 0
		self.is_debug = False
		self.sections = {}
		self.kern_imports = []
		self.cert = XbeImageCertificate()
		self.tls = XbeTlsHeader()
		self.libraries = {}
		self.library_features = {}
		self.logo = []
		self.junk_data = bytes()

		if data is not None:
			self._init_from_data(data)

	def _init_from_data(self, data):
		# Parse XBE header
		log.debug('Parsing image header at offset 0')
		self.header = XbeImageHeader.from_buffer_copy(data, 0)
		if self.header.image_header_size == ctypes.sizeof(XbeImageHeader):
			pass
		elif self.header.image_header_size == ctypes.sizeof(XbeImageHeaderExtended):
			self.header = XbeImageHeaderExtended.from_buffer_copy(data, 0)
		else:
			log.warning("Unexpected XBE image header size!")
			assert(self.header.image_header_size > ctypes.sizeof(XbeImageHeader))

		# FIXME: Validate magic
		# FIXME: Validate signature/integrity
		log.debug('Image Header:\n' + self.header.dumps(indent=2))

		self.header_data = data[0:self.header.headers_size]

		# Load debug pathname, filename
		self.pathname = self.get_cstring_from_offset(data, self.vaddr_to_file_offset(self.header.debug_pathname_addr))
		self.filename = self.get_cstring_from_offset(data, self.vaddr_to_file_offset(self.header.debug_filename_addr))
		self.filename_uc = self.get_wcstring_from_offset(data, self.vaddr_to_file_offset(self.header.debug_unicode_filename_addr))

		log.debug('Image Path: %s' % self.pathname)
		log.debug('Image Filename: %s' % self.filename)
		log.debug('Image Filename (Unicode): %s' % self.filename_uc)
		log.debug('Image Timestamp: ' + str(time.asctime(time.gmtime(self.header.timestamp))))

		# Load logo
		logo_offset = self.vaddr_to_file_offset(self.header.logo_addr)
		logo_end = logo_offset+self.header.logo_size
		self.logo = data[logo_offset:logo_end]

		# Identify extra junk in the header
		self.junk_data = data[logo_end:self.header.headers_size]
		if len(self.junk_data) > 0:
			log.debug('Image contained %d bytes of junk/pad in header' % len(self.junk_data))

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
		sec_hdr_offset = self.vaddr_to_file_offset(self.header.section_headers_addr)
		for i in range(self.header.section_count):
			# FIXME: Validate addresses

			# Load section header
			log.debug('Parsing section header at offset 0x%x' % sec_hdr_offset)
			sec_hdr = XbeSectionHeader.from_buffer_copy(data, sec_hdr_offset)

			# Get section name
			sec_name = self.get_cstring_from_offset(data, self.vaddr_to_file_offset(sec_hdr.section_name_addr), 'ascii')

			# Check for duplicate section names and rename
			count = 1
			sec_name_base = sec_name
			while sec_name in self.sections:
				count += 1
				sec_name = f'{sec_name_base}_{count}'
			if count > 1:
				log.warning('Duplicate section name %s found. Renaming to %s.', sec_name_base, sec_name)

			# Get section data
			sec_data_start = sec_hdr.raw_addr
			sec_data_end = sec_data_start + sec_hdr.raw_size
			sec_data = data[sec_data_start:sec_data_end]
			self.sections[sec_name] = XbeSection(sec_name, sec_hdr, sec_data)

			log.debug(('Section %d: %s\n' % (i, sec_name)) + sec_hdr.dumps(indent=2))
			sec_hdr_offset += ctypes.sizeof(XbeSectionHeader)

		# Load certificate
		cert_offset = self.vaddr_to_file_offset(self.header.certificate_addr)
		log.debug('Parsing image certificate at offset 0x%x' % cert_offset)
		# FIXME: Validate address
		self.cert = XbeImageCertificate.from_buffer_copy(data, cert_offset)		
		if self.cert.size == ctypes.sizeof(XbeImageCertificate):
			pass
		elif self.cert.size == ctypes.sizeof(XbeImageCertificateExtended):
			self.cert = XbeImageCertificateExtended.from_buffer_copy(data, cert_offset)
		else:
			log.warning("Unexpected XBE image certificate size!")
			assert(self.cert.size > ctypes.sizeof(XbeImageCertificate))


		self.title_name = str(self.cert.title_name, encoding='utf_16_le').rstrip('\x00')
		log.debug('XBE Title Name: ' + self.title_name)
		log.debug('XBE Title Id: ' + hex(self.cert.title_id))
		log.debug('Certificate:\n' + self.cert.dumps(indent=2))

		# Parse libraries
		if self.header.lib_versions_addr != 0:
			lib_ver_offset = self.vaddr_to_file_offset(self.header.lib_versions_addr)
			log.debug('Parsing library versions at offset 0x%x' % lib_ver_offset)
			for i in range(self.header.lib_versions_count):
				# FIXME: Validate address
				lib_ver = XbeLibraryVersion.from_buffer_copy(data, lib_ver_offset)
				lib = XbeLibrary(lib_ver)
				self.libraries[lib.name] = lib
				log.debug('Library %d: \'%s\' (%d.%d.%d)' % (i, lib.name, lib.header.ver_major, lib.header.ver_minor, lib.header.ver_build))
				lib_ver_offset += ctypes.sizeof(XbeLibraryVersion)

		# Parse library features
		if isinstance(self.header, XbeImageHeaderExtended) and self.header.lib_features_addr != 0:
			lib_feat_offset = self.vaddr_to_file_offset(self.header.lib_features_addr)
			log.debug('Parsing library features at offset 0x%x' % lib_feat_offset)
			for i in range(self.header.lib_features_count):
				# FIXME: Validate address
				lib_feat = XbeLibraryFeature(XbeLibraryFeatureDescriptor.from_buffer_copy(data, lib_feat_offset))
				self.library_features[lib_feat.name] = lib_feat
				log.debug('Library Feature %d: \'%s\' (%d.%d.%d)' % (i, lib_feat.name, lib_feat.header.ver_major, lib_feat.header.ver_minor, lib_feat.header.ver_build))
				lib_feat_offset += ctypes.sizeof(XbeLibraryFeatureDescriptor)

		# Parse TLS
		if self.header.tls_addr != 0:
			tls_offset = self.vaddr_to_file_offset(self.header.tls_addr)
			log.debug('Parsing TLS header at offset 0x%x' % tls_offset)
			self.tls = XbeTlsHeader.from_buffer_copy(data, tls_offset)
			log.debug('TLS:\n' + self.tls.dumps(indent=2))

		# Parse kernel imports
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

	def get_cstring_from_offset(self, data, offset, encoding=None):
		"""Read null-terminated string from `offset` in `data`"""
		name = bytearray()
		while True:
			x = data[offset]
			if x == 0: break
			name.append(x)
			offset += 1
		if encoding is not None:
			return str(name, encoding=encoding)
		else:
			return name

	def get_wcstring_from_offset(self, data, offset):
		"""Read null-terminated string from `offset` in `data`"""
		name = bytearray()
		while True:
			x = data[offset:offset+2]
			if x == b'\x00\x00': break
			name += x
			offset += 2
		return str(name, encoding='utf_16_le')

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

	def pack(self):
		"""Pack an XBE bottom-up"""
		# XBE's always reserve 4k for headers on file
		def round_up(x, align=0x1000):
			return (x+(align-1)) & ~(align-1)
		def off_to_addr(off):
			return self.header.base_addr + off

		raw_off = round_up(self.header.headers_size)

		# Construct section data
		section_data = bytes()
		for name in sorted(self.sections, key=lambda x: self.sections[x].header.virtual_addr):
			s = self.sections[name]
			print(name)
			print("EXPECTED %8x GOT %8x" % (s.header.raw_addr, raw_off))
			# assert(s.header.raw_addr == raw_off)
			s.header.raw_addr = raw_off
			section_data += s.data
			raw_off += len(s.data)

			# Align to 4k
			new_offset = round_up(raw_off)
			section_data += bytes(new_offset-raw_off)
			raw_off = new_offset

		#
		# Construct headers
		#
		headers_data = bytes()
		def do_append(data):
			nonlocal raw_off, headers_data
			old_off = raw_off
			headers_data += data
			raw_off += len(data)
			return off_to_addr(old_off)

		# Skip over these fixed-position headers for now while we construct
		# dependent data and fixup the offsets referred to in these structures
		raw_off = ctypes.sizeof(self.header)
		# self.header.image_header_size = raw_off

		self.header.certificate_addr = off_to_addr(raw_off)
		raw_off += ctypes.sizeof(self.cert)

		self.header.section_headers_addr = off_to_addr(raw_off)
		self.header.section_count = len(self.sections)
		raw_off += len(self.sections) * ctypes.sizeof(XbeSectionHeader)

		# Reference count addrs
		ref_count_addrs = {}
		for name in self.sections:
			s = self.sections[name].header
			for f in ['head_shared_page_ref_count_addr', 'tail_shared_page_ref_count_addr']:
				v = getattr(s, f)
				if v not in ref_count_addrs:
					ref_count_addrs[v] = 0
				ref_count_addrs[v] += 1
		for v in ref_count_addrs:
			ref_count_addrs[v] = do_append(b'\x00\x00')

		# Fixup
		for name in self.sections:
			s = self.sections[name].header
			s.head_shared_page_ref_count_addr = ref_count_addrs[s.head_shared_page_ref_count_addr]
			s.tail_shared_page_ref_count_addr = ref_count_addrs[s.tail_shared_page_ref_count_addr]

		#
		# Strings + Logo
		#

		# Section names
		for name in self.sections:
			addr = do_append(name.encode('ascii') + b'\x00')
			self.sections[name].header.section_name_addr = addr
		do_append(bytes(round_up(raw_off, 4)-raw_off)) # Align to 4 bytes

		# Library versions
		self.header.lib_versions_addr = off_to_addr(raw_off)
		self.header.lib_versions_count = len(self.libraries)
		self.header.kern_lib_version_addr = 0
		self.header.xapi_lib_version_addr = 0
		for l in self.libraries:
			addr = do_append(bytes(self.libraries[l].header))
			if l == 'XBOXKRNL':
				self.header.kern_lib_version_addr = addr
			elif l == 'XAPILIB':
				self.header.xapi_lib_version_addr = addr

		# Library features
		if isinstance(self.header, XbeImageHeaderExtended) and len(self.library_features) > 0:
			self.header.lib_features_count = len(self.library_features)
			self.header.lib_features_addr = off_to_addr(raw_off)
			for l in self.library_features:
				addr = do_append(bytes(self.library_features[l].header))

		# Debug paths
		self.header.debug_unicode_filename_addr = do_append(self.filename_uc.encode('utf_16_le') + b'\x00\x00')
		self.header.debug_pathname_addr = do_append(self.pathname + b'\x00')
		self.header.debug_filename_addr = self.header.debug_pathname_addr
		if self.pathname != '':
			self.header.debug_filename_addr += self.pathname.rfind(self.filename)
		do_append(bytes(round_up(raw_off, 4)-raw_off)) # Align to 4 bytes

		# Logo
		self.header.logo_addr = do_append(self.logo)
		do_append(bytes(round_up(raw_off, 4)-raw_off)) # Align to 4 bytes

		# Additional fixups

		# Sometimes this includes padding, other times it does not, what gives?
		# self.header.headers_size = raw_off
		do_append(bytes(round_up(raw_off)-raw_off)) # Align to 4K

		print('HEADERS SIZE = %x\n' % self.header.headers_size)
		print('RAW_OFF = %x\n' % raw_off)

		# Construct final image
		output = bytes()
		output += bytes(self.header)
		output += bytes(self.cert)
		for name in self.sections:
			s = self.sections[name].header
			print("writing section at %x" % len(output))
			output += bytes(s)
		output += headers_data
		output += section_data

		# MS XBEs seem to always add an extra page if the last page is completely filled
		# FIXME: Why?
		if output[-1] != 0:
			output += bytes(0x1000)

		with open('out.xbe', 'wb') as f:
			f.write(output)

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

class XbeLibraryFeature:
	def __init__(self, header):
		self.header = header
		self.name = str(self.header.name, encoding='ascii')

	def __repr__(self):
		return '<XbeFeature \'%s\' (%d.%d.%d)>' % (
			self.name,
			self.header.ver_major,
			self.header.ver_minor,
			self.header.ver_build)

class XprImageHeader(ctypes.LittleEndianStructure, StructurePrintMixin):
	_pack_ = 1
	_fields_ = [
		# XPR Header
		('magic',       ctypes.c_uint32), # XPR0
		('total_size',  ctypes.c_uint32),
		('header_size', ctypes.c_uint32),
		# D3D Texture
		('common',      ctypes.c_uint32),
		('data',        ctypes.c_uint32),
		('lock',        ctypes.c_uint32),
		('format',      ctypes.c_uint32),
		('size',        ctypes.c_uint32),
		('eoh',         ctypes.c_uint32), # 0xffffffff
		]

def mix(x, y, a):
	"""
	Linearly interpolate between x and y, returning x*(1-a) + y*a for all elements
	"""
	assert(len(x) == len(y))
	return tuple([x[i]*(1-a) + y[i]*(a) for i in range(len(x))])

def get_bits(x, h, l):
	"""
	Extract a bitrange from an integer
	"""
	return (x & ((1<<(h+1))-1)) >> l

def unpack_r5g6b5(h):
	"""
	Unpack a 16-bit (565) RGB as a real-value color tuple in the range of [0,1]
	"""
	r = get_bits(h, 15, 11)
	g = get_bits(h, 10,  5)
	b = get_bits(h,  4,  0)
	return (r/31, g/63, b/31, 1)

def decode_bc1(w, h, data):
	"""
	Decode a BC1 (aka DXT1) compressed image to a list of pixel real-value color
	tuples

	More information about BC1 can be found at: https://docs.microsoft.com/en-us/windows/win32/direct3d10/d3d10-graphics-programming-guide-resources-block-compression#bc1
	"""
	assert(w % 4 == 0)
	assert(h % 4 == 0)
	blocks_per_row = w // 4
	blocks_per_col = h // 4
	num_blocks = blocks_per_row * blocks_per_col
	num_bytes = num_blocks * 8
	assert(len(data) >= num_bytes)
	pixels = [(0,0,0,0) for _ in range(w*h)]

	# Decode blocks
	for block_idx in range(num_blocks):
		block_y = (block_idx // blocks_per_row) * 4
		block_x = (block_idx % blocks_per_row) * 4
		block_data = data[(block_idx*8):(block_idx*8+8)]

		c0, c1, indices = struct.unpack('<HHI', block_data[0:8])
		alpha_enabled = c0 <= c1
		c0, c1 = unpack_r5g6b5(c0), unpack_r5g6b5(c1)

		if alpha_enabled:
			transparent = (0, 0, 0, 0)
			colors = (c0, c1, mix(c0, c1, 1/2), transparent)
		else:
			colors = (c0, c1, mix(c0, c1, 1/3), mix(c0, c1, 2/3))

		for y in range(4):
			for x in range(4):
				bit_off = y*8 + x*2
				color_idx = get_bits(indices, bit_off+1, bit_off)
				pixels[(block_y+y)*w + (block_x+x)] = colors[color_idx]

	return pixels

def decode_xpr_image(data):
	"""
	Decode an XPR (Xbox Packed Resource) image
	"""
	log.debug('Parsing XPR header')
	hdr = XprImageHeader.from_buffer_copy(data, 0)
	log.debug(hdr)

	assert(hdr.magic == 0x30525058), "Invalid header magic"
	assert(hdr.eoh == 0xffffffff), "Invalid end-of-header"
	assert(hdr.total_size == len(data)), "Invalid size"
	assert(get_bits(hdr.format, 15, 8) == 0x0c), "Format is not DXT1"
	assert(get_bits(hdr.format, 7, 4) == 2), "Dimensionality is not 2"

	w = 1 << get_bits(hdr.format, 23, 20)
	h = 1 << get_bits(hdr.format, 27, 24)
	log.debug('Image is %dx%d' % (w,h))

	return (w, h, decode_bc1(w, h, data[hdr.header_size:]))

def encode_bmp(w, h, pixels):
	"""
	Encode a standard Windows BMP Image File

	https://en.wikipedia.org/wiki/BMP_file_format
	"""
	enc = b''
	for y in range(h):
		y = h-y-1 # Bitmap encodes the image "bottom-up"
		for x in range(w):
			r, g, b, a = pixels[y*w + x]
			enc += struct.pack('<BBBB',
				int(255*b), int(255*g), int(255*r), int(255*a))

	# Encode BITMAPV5HEADER
	# https://docs.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapv5header
	hdr = b'BM' + struct.pack('<3I 3I2H11I48x I12x',
		# Bitmap File Header
		14+124+len(enc), # Total size
		0,               # Reserved
		14+124,          # Offset to pixel array
		# DIB Header
		124,             # sizeof(BITMAPV5INFOHEADER)
		w, h,            # Image dimensions
		1,               # No. color planes
		32,              # BPP
		3,               # BI_BITFIELDS
		len(enc),        # Image size
		2835, 2835,      # Horizontal, Vertical Resolution (72DPI)
		0,               # Colors in palette (0=2^n)
		0,               # Important colors (0=all colors)
		0x00ff0000,      # Red channel bitmask
		0x0000ff00,      # Green channel bitmask
		0x000000ff,      # Blue channel bitmask
		0xff000000,      # Alpha channel bitmask
		0x73524742,      # sRGB color space
		4                # LCS_GM_IMAGES
		)

	return hdr + enc
