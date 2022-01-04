/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
#include <windows.h>

#include "ofc/types.h"
#include "ofc/handle.h"
#include "ofc/libc.h"
#include "ofc/path.h"
#include "ofc/lock.h"
#include "ofc/thread.h"

#include "ofc/heap.h"
#include "ofc/fs.h"

/**
 * \defgroup fs_windows Windows File Interface
 *
 */

/** \{ */
typedef struct 
{
  HANDLE fileHandle ;
  WIN32_FIND_DATA nextFindFileData ;
  OFC_BOOL nextRet ;
  OFC_DWORD nextLastError ;
} OFC_FS_WIN32_CONTEXT ;

static FILE_INFO_BY_HANDLE_CLASS 
OfcClass2WinClass[OfcMaximumFileInfoByHandlesClass] =
  {
    FileBasicInfo,
    FileStandardInfo,
    FileNameInfo,
    FileRenameInfo,
    FileDispositionInfo,
    FileAllocationInfo,
    FileEndOfFileInfo,
    FileStreamInfo,
    FileCompressionInfo,
    FileAttributeTagInfo,
    FileIdBothDirectoryInfo,
    FileIdBothDirectoryRestartInfo
  } ;

static OFC_HANDLE OfcFSWin32CreateFile (OFC_LPCTSTR lpFileName,
					  OFC_DWORD dwDesiredAccess,
					  OFC_DWORD dwShareMode,
					  OFC_LPSECURITY_ATTRIBUTES 
					  lpSecAttributes,
					  OFC_DWORD dwCreationDisposition,
					  OFC_DWORD dwFlagsAndAttributes,
					  OFC_HANDLE hTemplateFile)
{
  OFC_HANDLE ret ;
  OFC_FS_WIN32_CONTEXT *context ;
  OFC_FS_WIN32_CONTEXT *template ;
  HANDLE templateHandle ;
  OFC_BOOL retry ;
  OFC_INT i ;

  templateHandle = NULL ;

  if (hTemplateFile != OFC_HANDLE_NULL)
    {
      template = ofc_handle_lock (hTemplateFile) ;
      if (template != OFC_NULL)
	{
	  templateHandle = template->fileHandle ;
	  ofc_handle_unlock (hTemplateFile) ;
	}
    }

  context = ofc_malloc (sizeof (OFC_FS_WIN32_CONTEXT)) ;
  context->fileHandle = OFC_HANDLE_NULL ;

  retry = OFC_TRUE ;
  for (i = 0 ; retry ; i++)
    {
      context->fileHandle = CreateFileW (lpFileName,
					 dwDesiredAccess,
					 dwShareMode,
					 (LPSECURITY_ATTRIBUTES)
					 lpSecAttributes,
					 dwCreationDisposition,
					 dwFlagsAndAttributes,
					 templateHandle) ;
      if ((context->fileHandle == NULL || 
	   context->fileHandle == INVALID_HANDLE_VALUE) && 
	  GetLastError() == ERROR_SHARING_VIOLATION && i < 5)
	Sleep (1000) ;
      else
	retry = OFC_FALSE ;
    }

  if (context->fileHandle == NULL || 
      context->fileHandle == INVALID_HANDLE_VALUE)
    {
      ofc_thread_set_variable
      ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;
      ofc_free (context) ;
      ret = OFC_INVALID_HANDLE_VALUE ;
    }
  else
    {
      ret = ofc_handle_create (OFC_HANDLE_FSWIN32_FILE, context) ;
    }

  return (ret) ;
}

static OFC_BOOL 
OfcFSWin32CreateDirectory (OFC_LPCTSTR lpPathName,
			    OFC_LPSECURITY_ATTRIBUTES lpSecurityAttr) 
{
  OFC_BOOL ret ;

  ret = CreateDirectory (lpPathName, 
			 (LPSECURITY_ATTRIBUTES) lpSecurityAttr) ;

  if (ret == OFC_FALSE)
    ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

  return (ret) ;
}

static OFC_BOOL OfcFSWin32WriteFile (OFC_HANDLE hFile,
				       OFC_LPCVOID lpBuffer,
				       OFC_DWORD nNumberOfBytesToWrite,
				       OFC_LPDWORD lpNumberOfBytesWritten,
				       OFC_HANDLE hOverlapped)
{
  BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;
  OVERLAPPED *Overlapped ;

  context = ofc_handle_lock (hFile) ;

  if (context != OFC_NULL)
    {
      Overlapped = OFC_NULL ;
      if (hOverlapped != OFC_HANDLE_NULL)
	{
	  Overlapped = ofc_handle_lock (hOverlapped) ;
	  if (Overlapped != OFC_NULL)
	    ofc_handle_unlock (hOverlapped) ;
        }
      ret = WriteFile (context->fileHandle,
		       lpBuffer,
		       nNumberOfBytesToWrite,
		       lpNumberOfBytesWritten,
		       Overlapped) ;
      if (ret == OFC_FALSE)
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;
      ofc_handle_unlock (hFile) ;
    }
  else
    ret = OFC_FALSE ;

  return (ret) ;
}

static OFC_BOOL OfcFSWin32ReadFile (OFC_HANDLE hFile,
				      OFC_LPVOID lpBuffer,
				      OFC_DWORD nNumberOfBytesToRead,
				      OFC_LPDWORD lpNumberOfBytesRead,
				      OFC_HANDLE hOverlapped)
{
  BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;
  OVERLAPPED *Overlapped ;

  context = ofc_handle_lock (hFile) ;

  if (context != OFC_NULL)
    {
      Overlapped = OFC_NULL ;
      if (hOverlapped != OFC_HANDLE_NULL)
	{
	  Overlapped = ofc_handle_lock (hOverlapped) ;
	  if (Overlapped != OFC_NULL)
	    ofc_handle_unlock (hOverlapped) ;
        }

      ret = ReadFile (context->fileHandle,
		      lpBuffer,
		      nNumberOfBytesToRead,
		      lpNumberOfBytesRead,
		      Overlapped) ;
      if (ret == OFC_FALSE)
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;
      ofc_handle_unlock (hFile) ;
    }
  else
    ret = OFC_FALSE ;

  return (ret) ;
}

static OFC_BOOL OfcFSWin32CloseHandle (OFC_HANDLE hFile)
{
  BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;

  context = ofc_handle_lock (hFile) ;

  if (context != OFC_NULL)
    {
      ret = CloseHandle (context->fileHandle) ;
      if (ret == OFC_TRUE)
	{
	  ofc_handle_destroy (hFile) ;
	  ofc_free (context) ;
	}
      else
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

      ofc_handle_unlock (hFile) ;
    }
  else
    ret = OFC_FALSE ;

  return (ret) ;

}

OFC_BOOL OfcFSWin32DeleteFile (OFC_LPCTSTR lpFileName) 
{
  OFC_BOOL ret ;

  ret = DeleteFileW (lpFileName) ;
  if (ret == OFC_FALSE)
    ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

  return (ret) ;
}

OFC_BOOL OfcFSWin32RemoveDirectory (OFC_LPCTSTR lpPathName) 
{
  OFC_BOOL ret ;

  ret = RemoveDirectory (lpPathName) ;
  if (ret == OFC_FALSE)
    ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

  return (ret) ;
}

OFC_HANDLE OfcFSWin32FindFirstFile (OFC_LPCTSTR lpFileName,
				      OFC_LPWIN32_FIND_DATAW lpFindFileData,
				      OFC_BOOL *more) 
{
  OFC_HANDLE hRet ;
  OFC_FS_WIN32_CONTEXT *context ;

  context = ofc_malloc (sizeof (OFC_FS_WIN32_CONTEXT)) ;
  context->fileHandle = FindFirstFile (lpFileName, 
				       (LPWIN32_FIND_DATA) lpFindFileData) ;

  *more = OFC_FALSE ;
  if (context->fileHandle == NULL || 
      context->fileHandle == INVALID_HANDLE_VALUE)
    {
      ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

      ofc_free (context) ;
      hRet = OFC_HANDLE_NULL ;
    }
  else
    {
      context->nextRet = FindNextFile (context->fileHandle, 
				       &context->nextFindFileData) ;
      if (context->nextRet == OFC_TRUE)
	*more = OFC_TRUE ;
      else
	context->nextLastError = GetLastError() ;

      hRet = ofc_handle_create (OFC_HANDLE_FSWIN32_FILE, context) ;
    }

  return (hRet) ;
}

OFC_BOOL OfcFSWin32FindNextFile (OFC_HANDLE hFindFile,
				   OFC_LPWIN32_FIND_DATAW lpFindFileData,
				   OFC_BOOL *more) 
{
  BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;

  context = ofc_handle_lock (hFindFile) ;

  ret = OFC_FALSE ;
  *more = OFC_FALSE ;
  if (context != OFC_NULL)
    {
      ofc_memcpy (lpFindFileData, &context->nextFindFileData,
		   sizeof (WIN32_FIND_DATA)) ;
      ret = context->nextRet ;
      if (ret == OFC_FALSE)
	ofc_thread_set_variable (OfcLastError, 
			       (OFC_DWORD_PTR) context->nextLastError) ;

      context->nextRet = FindNextFile (context->fileHandle, 
				       &context->nextFindFileData) ;
      if (context->nextRet == OFC_TRUE)
	*more = OFC_TRUE ;
      else
	context->nextLastError = OfcGetLastError() ;

      ofc_handle_unlock (hFindFile) ;
    }

  return (ret) ;
}

OFC_BOOL OfcFSWin32FindClose (OFC_HANDLE hFindFile) 
{
  BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;

  context = ofc_handle_lock (hFindFile) ;

  ret = OFC_FALSE ;
  if (context != OFC_NULL)
    {
      ret = FindClose (context->fileHandle) ;
      if (ret == OFC_TRUE)
	{
	  ofc_handle_destroy (hFindFile) ;
	  ofc_free (context) ;
	}
      else
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

      ofc_handle_unlock (hFindFile) ;
    }

  return (ret) ;
}

OFC_BOOL OfcFSWin32FlushFileBuffers (OFC_HANDLE hFile) 
{
  BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;

  context = ofc_handle_lock (hFile) ;

  ret = OFC_FALSE ;
  if (context != OFC_NULL)
    {
      ret = FlushFileBuffers (context->fileHandle) ;
      ofc_handle_unlock (hFile) ;
      if (ret == OFC_FALSE)
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;
    }

  return (ret) ;
}

OFC_BOOL OfcFSWin32GetFileAttributesEx (OFC_LPCTSTR lpFileName,
					  OFC_GET_FILEEX_INFO_LEVELS 
					  fInfoLevelId,
					  OFC_LPVOID lpFileInformation) 
{
  OFC_BOOL ret ;

  ret = GetFileAttributesEx (lpFileName, fInfoLevelId, lpFileInformation) ;
  if (ret == OFC_FALSE)
    ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

  return (ret) ;
}

OFC_BOOL OfcFSWin32GetFileInformationByHandleEx 
(OFC_HANDLE hFile,
 OFC_FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
 OFC_LPVOID lpFileInformation,
 OFC_DWORD dwBufferSize) 
{
  BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;

  ret = OFC_FALSE ;

  context = ofc_handle_lock (hFile) ;
  if (context != OFC_NULL)
    {
      ret = 
	GetFileInformationByHandleEx ((HANDLE) context->fileHandle,
				      OfcClass2WinClass[FileInformationClass],
				      (LPVOID) lpFileInformation,
				      (DWORD) dwBufferSize) ;
      if (ret == OFC_FALSE)
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

      ofc_handle_unlock (hFile) ;
    }

  return ((OFC_BOOL) ret) ;
}

OFC_BOOL OfcFSWin32MoveFile (OFC_LPCTSTR lpExistingFileName,
			       OFC_LPCTSTR lpNewFileName) 
{
  OFC_BOOL ret ;

  ret = MoveFileW (lpExistingFileName, lpNewFileName) ;
  if (ret == OFC_FALSE)
    ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

  return (ret) ;
}

static OFC_HANDLE OfcFSWin32CreateOverlapped (OFC_VOID)
{
  OVERLAPPED *Overlapped ;
  OFC_HANDLE hRet ;

  hRet = OFC_HANDLE_NULL ;
  Overlapped = ofc_malloc (sizeof (OVERLAPPED)) ;
  if (Overlapped != OFC_NULL)
    {
      BlueCmemset (Overlapped, '\0', sizeof (OVERLAPPED)) ;
      Overlapped->hEvent = CreateEvent (NULL, TRUE, FALSE, NULL) ;
      hRet = ofc_handle_create (OFC_HANDLE_FSWIN32_OVERLAPPED, Overlapped) ;
    }
  return (hRet) ;
 }

static OFC_VOID OfcFSWin32DestroyOverlapped (OFC_HANDLE hOverlapped)
{
  OVERLAPPED *Overlapped ;

  Overlapped = ofc_handle_lock (hOverlapped) ;
  if (Overlapped != OFC_NULL)
    {
      ofc_handle_destroy (hOverlapped) ;
      ofc_handle_unlock (hOverlapped) ;
      CloseHandle (Overlapped->hEvent) ;
      ofc_free (Overlapped) ;
    }
}

static OFC_VOID OfcFSWin32SetOverlappedOffset (OFC_HANDLE hOverlapped,
						 OFC_OFFT offset)
{
  OVERLAPPED *Overlapped ;

  Overlapped = ofc_handle_lock (hOverlapped) ;
  if (Overlapped != OFC_NULL)
    {
      Overlapped->Offset = OFC_LARGE_INTEGER_LOW(offset) ;
      Overlapped->OffsetHigh = OFC_LARGE_INTEGER_HIGH(offset) ;
    }
}
  
static OFC_BOOL OfcFSWin32GetOverlappedResult (OFC_HANDLE hFile,
						 OFC_HANDLE hOverlapped,
						 OFC_LPDWORD 
						 lpNumberOfBytesTransferred,
						 OFC_BOOL bWait) 
{
  BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;
  OVERLAPPED *Overlapped ;

  context = ofc_handle_lock (hFile) ;

  ret = OFC_FALSE ;
  if (context != OFC_NULL)
    {
      Overlapped = ofc_handle_lock (hOverlapped) ;
      if (Overlapped != OFC_NULL)
	ofc_handle_unlock (hOverlapped) ;

      ret = GetOverlappedResult (context->fileHandle,
                                 Overlapped,
                                 lpNumberOfBytesTransferred,
                                 bWait) ;
      if (ret == OFC_FALSE)
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;
      ofc_handle_unlock (hFile) ;
    }

  return (ret) ;
}

OFC_BOOL OfcFSWin32SetEndOfFile (OFC_HANDLE hFile) 
{
  BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;

  context = ofc_handle_lock (hFile) ;

  ret = OFC_FALSE ;
  if (context != OFC_NULL)
    {
      ret = SetEndOfFile (context->fileHandle) ;
      if (ret == OFC_FALSE)
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;
      ofc_handle_unlock (hFile) ;
    }

  return (ret) ;
}

OFC_BOOL OfcFSWin32SetFileAttributes (OFC_LPCTSTR lpFileName,
					OFC_DWORD dwFileAttributes)
{
  OFC_BOOL ret ;

  ret = SetFileAttributes (lpFileName, dwFileAttributes) ;
  if (ret == OFC_FALSE)
    ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

  return (ret) ;
}

OFC_BOOL OfcFSWin32SetFileInformationByHandle (OFC_HANDLE hFile,
						 OFC_FILE_INFO_BY_HANDLE_CLASS
						 FileInformationClass,
						 OFC_LPVOID lpFileInformation,
						 OFC_DWORD dwBufferSize) 
{
  BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;

  ret = OFC_FALSE ;

  context = ofc_handle_lock (hFile) ;
  if (context != OFC_NULL)
    {
      ret = 
	SetFileInformationByHandle ((HANDLE) context->fileHandle,
				    OfcClass2WinClass[FileInformationClass],
				    lpFileInformation,
				    (DWORD) dwBufferSize) ;
      if (ret == OFC_FALSE)
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;
      ofc_handle_unlock (hFile) ;
    }

  return ((OFC_BOOL) ret) ;
}

OFC_DWORD OfcFSWin32SetFilePointer (OFC_HANDLE hFile,
				      OFC_LONG lDistanceToMove,
				      OFC_PLONG lpDistanceToMoveHigh,
				      OFC_DWORD dwMoveMethod) 
{
  OFC_DWORD ret ;
  OFC_FS_WIN32_CONTEXT *context ;

  context = ofc_handle_lock (hFile) ;

  ret = OFC_INVALID_SET_FILE_POINTER ;
  if (context != OFC_NULL)
    {
      ret = SetFilePointer (context->fileHandle,
                            lDistanceToMove,
                            lpDistanceToMoveHigh,
                            dwMoveMethod) ;
      if (ret == OFC_INVALID_SET_FILE_POINTER)
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

      ofc_handle_unlock (hFile) ;
    }

  return (ret) ;
}

static OFC_BOOL 
OfcFSWin32TransactNamedPipe (OFC_HANDLE hFile,
			      OFC_LPVOID lpInBuffer,
			      OFC_DWORD nInBufferSize,
			      OFC_LPVOID lpOutBuffer,
			      OFC_DWORD nOutBufferSize,
			      OFC_LPDWORD lpBytesRead,
			      OFC_HANDLE hOverlapped)
{
  BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;
  OVERLAPPED *Overlapped ;

  context = ofc_handle_lock (hFile) ;

  if (context != OFC_NULL)
    {
      Overlapped = OFC_NULL ;
      if (hOverlapped != OFC_HANDLE_NULL)
	{
	  Overlapped = ofc_handle_lock (hOverlapped) ;
	  if (Overlapped != OFC_NULL)
	    ofc_handle_unlock (hOverlapped) ;
        }

      ret = TransactNamedPipe (context->fileHandle,
			       lpInBuffer,
			       nInBufferSize,
			       lpOutBuffer,
			       nOutBufferSize,
			       lpBytesRead,
			       Overlapped) ;
      if (ret == OFC_FALSE)
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

      ofc_handle_unlock (hFile) ;
    }
  else
    ret = OFC_FALSE ;

  return (ret) ;
}

static OFC_BOOL 
OfcFSWin32GetDiskFreeSpace (OFC_LPCTSTR lpRootPathName,
			     OFC_LPDWORD lpSectorsPerCluster,
			     OFC_LPDWORD lpBytesPerSector,
			     OFC_LPDWORD lpNumberOfFreeClusters,
			     OFC_LPDWORD lpTotalNumberOfClusters) 
{
  OFC_BOOL ret ;

  ret = GetDiskFreeSpace (lpRootPathName,
			  lpSectorsPerCluster,
			  lpBytesPerSector,
			  lpNumberOfFreeClusters,
			  lpTotalNumberOfClusters) ;

  if (ret == OFC_FALSE)
    ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

  return (ret) ;
}

static OFC_BOOL
OfcFSWin32GetVolumeInformation (OFC_LPCTSTR lpRootPathName,
				 OFC_LPTSTR lpVolumeNameBuffer,
				 OFC_DWORD nVolumeNameSize,
				 OFC_LPDWORD lpVolumeSerialNumber,
				 OFC_LPDWORD lpMaximumComponentLength,
				 OFC_LPDWORD lpFileSystemFlags,
				 OFC_LPTSTR lpFileSystemName,
				 OFC_DWORD nFileSystemName) 
{
  OFC_BOOL ret ;
  OFC_PATH *path ;
  OFC_CHAR *lpRoot ;
  OFC_TCHAR *lptRoot ;
  OFC_INT count ;

  if (nVolumeNameSize == 0)
    lpVolumeNameBuffer = OFC_NULL ;

  /*
   * We've got to find just the device name
   */
  path = ofc_path_createW (lpRootPathName) ;

  count = 0 ;
  count = ofc_snprintf (OFC_NULL, count, "%S:\\", ofc_path_device(path)) ;
  count++ ;
  lpRoot = ofc_malloc (count*sizeof(OFC_CHAR)) ;
  ofc_snprintf (lpRoot, count, "%S:\\", ofc_path_device(path)) ;
  lptRoot = ofc_cstr2tstr (lpRoot) ;
  ofc_free (lpRoot) ;

  ret = GetVolumeInformation (lptRoot,
			      lpVolumeNameBuffer,
			      nVolumeNameSize,
			      lpVolumeSerialNumber,
			      lpMaximumComponentLength,
			      lpFileSystemFlags,
			      lpFileSystemName,
			      nFileSystemName) ;
  if (ret == OFC_FALSE)
    ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;
    
  ofc_free (lptRoot) ;
  ofc_path_delete (path) ;
  return (ret) ;
}

/**
 * Unlock a region in a file
 * 
 * \param hFile
 * File Handle to unlock 
 *
 * \param length_low
 * the low order 32 bits of the length of the region
 *
 * \param length_high
 * the high order 32 bits of the length of the region
 *
 * \param overlapped
 * The overlapped structure which specifies the offset
 *
 * \returns
 * OFC_TRUE if successful, OFC_FALSE otherwise
 */
static OFC_BOOL OfcFSWin32UnlockFileEx (OFC_HANDLE hFile, 
					  OFC_UINT32 length_low, 
					  OFC_UINT32 length_high,
					  OFC_HANDLE hOverlapped)
{
  OFC_BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;
  OVERLAPPED *Overlapped ;

  context = ofc_handle_lock (hFile) ;

  ret = OFC_FALSE ;
  if (context != OFC_NULL)
    {
      Overlapped = OFC_NULL ;
      if (hOverlapped != OFC_HANDLE_NULL)
	{
	  Overlapped = ofc_handle_lock (hOverlapped) ;
	  if (Overlapped != OFC_NULL)
	    ofc_handle_unlock (hOverlapped) ;
        }

      ret = UnlockFileEx (context->fileHandle, 0,
			  length_low, length_high, Overlapped) ;

      if (ret == OFC_FALSE)
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

      ofc_handle_unlock (hFile) ;
    }

  return (ret) ;
}

/**
 * Lock a region of a file
 * 
 * \param hFile
 * Handle to file to unlock region in 
 *
 * \param flags
 * Flags for lock
 *
 * \param length_low
 * Low order 32 bits of length of region
 *
 * \param length_high
 * High order 32 bits of length of region
 *
 * \param overlapped
 * Pointer to overlapped structure containing offset of region
 *
 * \returns
 * OFC_TRUE if successful, OFC_FALSE otherwise
 */
static OFC_BOOL OfcFSWin32LockFileEx (OFC_HANDLE hFile, OFC_DWORD flags,
					OFC_DWORD length_low, 
					OFC_DWORD length_high,
					OFC_HANDLE hOverlapped)
{
  OFC_BOOL ret ;
  OFC_FS_WIN32_CONTEXT *context ;
  OVERLAPPED *Overlapped ;

  context = ofc_handle_lock (hFile) ;

  ret = OFC_FALSE ;
  if (context != OFC_NULL)
    {
      Overlapped = OFC_NULL ;
      if (hOverlapped != OFC_HANDLE_NULL)
	{
	  Overlapped = ofc_handle_lock (hOverlapped) ;
	  if (Overlapped != OFC_NULL)
	    ofc_handle_unlock (hOverlapped) ;
        }

      ret = LockFileEx (context->fileHandle, flags, 0,
			length_low, length_high, Overlapped) ;

      if (ret == OFC_FALSE)
	ofc_thread_set_variable (OfcLastError, (OFC_DWORD_PTR) GetLastError()) ;

      ofc_handle_unlock (hFile) ;
    }

  return (ret) ;
}

static OFC_BOOL OfcFSWin32Dismount(OFC_LPCTSTR filename) {
    OFC_BOOL ret;

    ret = OFC_TRUE;
    return (ret);
}

static OFC_FILE_FSINFO OfcFSWin32Info =
  {
    &OfcFSWin32CreateFile,
    &OfcFSWin32DeleteFile,
    &OfcFSWin32FindFirstFile,
    &OfcFSWin32FindNextFile,
    &OfcFSWin32FindClose,
    &OfcFSWin32FlushFileBuffers,
    &OfcFSWin32GetFileAttributesEx,
    &OfcFSWin32GetFileInformationByHandleEx,
    &OfcFSWin32MoveFile,
    &OfcFSWin32GetOverlappedResult,
    &OfcFSWin32CreateOverlapped,
    &OfcFSWin32DestroyOverlapped,
    &OfcFSWin32SetOverlappedOffset,
    &OfcFSWin32SetEndOfFile,
    &OfcFSWin32SetFileAttributes,
    &OfcFSWin32SetFileInformationByHandle,
    &OfcFSWin32SetFilePointer,
    &OfcFSWin32WriteFile,
    &OfcFSWin32ReadFile,
    &OfcFSWin32CloseHandle,
    &OfcFSWin32TransactNamedPipe,
    &OfcFSWin32GetDiskFreeSpace,
    &OfcFSWin32GetVolumeInformation,
    &OfcFSWin32CreateDirectory,
    &OfcFSWin32RemoveDirectory,
    &OfcFSWin32UnlockFileEx,
    &OfcFSWin32LockFileEx,
    &OfcFSWin32Dismount,
    OFC_NULL
  } ;

OFC_VOID OfcFSWin32Startup (OFC_VOID)
{
  BlueFSRegister (OFC_FST_WIN32, &OfcFSWin32Info) ;
}

HANDLE OfcFSWin32GetOverlappedEvent (OFC_HANDLE hOverlapped)
{
  HANDLE handle ;
  OVERLAPPED *Overlapped ;

  handle = INVALID_HANDLE_VALUE ;
  
  if (hOverlapped != OFC_HANDLE_NULL)
    {
      Overlapped = ofc_handle_lock (hOverlapped) ;
      if (Overlapped != OFC_NULL)
	handle = Overlapped->hEvent ;
    }
  return (handle) ;
}

HANDLE OfcFSWin32GetHandle (OFC_HANDLE hFile) 
{
  HANDLE handle ;
  OFC_FS_WIN32_CONTEXT *context ;

  context = ofc_handle_lock (hFile) ;

  handle = INVALID_HANDLE_VALUE ;
  if (context != OFC_NULL)
    {
      handle = context->fileHandle ;
      ofc_handle_unlock (hFile) ;
    }
  return (handle) ;
}

/** \} */
