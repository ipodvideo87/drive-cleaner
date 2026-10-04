#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyze WizTree and WinDirStat CSV exports and find cleanup candidates."""

import csv
import heapq
import hashlib
import ntpath
import os
import shutil
import subprocess
import sys
import json
import re
import tempfile
from datetime import datetime
from functools import lru_cache
from pathlib import Path

import scan
from error_messages import describe_error

_CLEANUP_NATIVE_GUARD_SOURCE = r"""
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class __CLASS_NAME__
{
    private const uint DeleteAccess = 0x00010000;
    private const uint GenericRead = 0x80000000;
    private const uint ReadAttributes = 0x00000080;
    private const uint WriteAttributes = 0x00000100;
    private const uint ShareRead = 0x00000001;
    private const uint ShareAll = 0x00000007;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint BackupSemantics = 0x02000000;
    private const uint AttributeDirectory = 0x00000010;
    private const uint AttributeReadOnly = 0x00000001;
    private const uint AttributeReparsePoint = 0x00000400;
    private const int FileDispositionInfo = 4;
    private const int FileBasicInfo = 0;
    private const int ErrorHandleEof = 38;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FindStreamData
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string StreamName;
    }

    private sealed class NamedStreamSnapshot
    {
        public string Name;
        public long Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDisposition
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInformation
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle, out FileInformation information);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool LockFileEx(
        SafeFileHandle handle, uint flags, uint reserved, uint bytesToLockLow,
        uint bytesToLockHigh, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle handle, int informationClass, ref FileDisposition information,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle handle, int informationClass, out FileBasicInformation information,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle handle, int informationClass, ref FileBasicInformation information,
        uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(
        string fileName, int informationLevel, out FindStreamData streamData, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextStreamW(IntPtr findHandle, out FindStreamData streamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindClose(IntPtr findHandle);

    private sealed class LockedPath : IDisposable
    {
        public SafeFileHandle Target;
        public readonly List<SafeFileHandle> Parents = new List<SafeFileHandle>();

        public void Dispose()
        {
            if (Target != null) Target.Dispose();
            for (int index = Parents.Count - 1; index >= 0; index--)
                Parents[index].Dispose();
        }
    }

    private static string ExtendedPath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        if (fullPath.StartsWith("\\\\?\\", StringComparison.Ordinal)) return fullPath;
        if (fullPath.StartsWith("\\\\", StringComparison.Ordinal))
            return "\\\\?\\UNC\\" + fullPath.Substring(2);
        return "\\\\?\\" + fullPath;
    }

    private static SafeFileHandle Open(string path, uint access)
    {
        return Open(path, access, ShareRead);
    }

    private static SafeFileHandle Open(string path, uint access, uint shareMode)
    {
        SafeFileHandle handle = CreateFile(
            ExtendedPath(path), access, shareMode, IntPtr.Zero, OpenExisting,
            OpenReparsePoint | BackupSemantics, IntPtr.Zero);
        if (handle == null || handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            if (handle != null) handle.Dispose();
            throw new Win32Exception(error, "Could not securely open a cleanup path.");
        }
        return handle;
    }

    private static FileInformation Information(SafeFileHandle handle)
    {
        FileInformation information;
        if (!GetFileInformationByHandle(handle, out information))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not inspect a cleanup path.");
        return information;
    }

    private static void RequireOrdinaryType(FileInformation information, bool isDirectory)
    {
        if ((information.Attributes & AttributeReparsePoint) != 0)
            throw new IOException("A cleanup path became a reparse point; refusing deletion");
        bool actualDirectory = (information.Attributes & AttributeDirectory) != 0;
        if (actualDirectory != isDirectory)
            throw new IOException("A cleanup path changed type; refusing deletion");
    }

    private static string Identity(FileInformation information)
    {
        return String.Format(
            "{0:X8}:{1:X8}:{2:X8}", information.VolumeSerialNumber,
            information.FileIndexHigh, information.FileIndexLow);
    }

    private static long FileSize(FileInformation information)
    {
        return ((long)information.FileSizeHigh << 32) | information.FileSizeLow;
    }

    private static List<NamedStreamSnapshot> EnumerateNamedStreams(string path)
    {
        FindStreamData data;
        IntPtr findHandle = FindFirstStreamW(ExtendedPath(path), 0, out data, 0);
        if (findHandle == new IntPtr(-1))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == ErrorHandleEof || error == 87) return new List<NamedStreamSnapshot>();
            throw new Win32Exception(error, "Could not enumerate a cleanup item's named data streams.");
        }

        List<NamedStreamSnapshot> streams = new List<NamedStreamSnapshot>();
        HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            while (true)
            {
                string name = data.StreamName;
                if (!String.IsNullOrEmpty(name) && !String.Equals(name, "::$DATA", StringComparison.OrdinalIgnoreCase))
                {
                    if (!name.StartsWith(":", StringComparison.Ordinal) ||
                        !name.EndsWith(":$DATA", StringComparison.OrdinalIgnoreCase) || data.StreamSize < 0 ||
                        !names.Add(name))
                        throw new IOException("Could not safely identify a named data stream; refusing cleanup");
                    streams.Add(new NamedStreamSnapshot { Name = name, Length = data.StreamSize });
                }

                if (!FindNextStreamW(findHandle, out data))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ErrorHandleEof) break;
                    throw new Win32Exception(error, "Could not finish enumerating a cleanup item's named data streams.");
                }
            }
        }
        finally
        {
            FindClose(findHandle);
        }

        streams.Sort(delegate(NamedStreamSnapshot left, NamedStreamSnapshot right)
        {
            return StringComparer.OrdinalIgnoreCase.Compare(left.Name, right.Name);
        });
        return streams;
    }

    private static bool SameNamedStreams(
        List<NamedStreamSnapshot> left, List<NamedStreamSnapshot> right)
    {
        if (left.Count != right.Count) return false;
        for (int index = 0; index < left.Count; index++)
        {
            if (left[index].Length != right[index].Length ||
                !String.Equals(left[index].Name, right[index].Name, StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

    private static string NamedStreamPath(string path, string streamName)
    {
        string fullPath = Path.GetFullPath(path);
        string root = Path.GetPathRoot(fullPath);
        if (!String.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase))
            fullPath = fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return fullPath + streamName;
    }

    private static void RequireNamedStreamsUnchanged(
        string path, List<NamedStreamSnapshot> expectedStreams)
    {
        List<NamedStreamSnapshot> currentStreams = EnumerateNamedStreams(path);
        if (!SameNamedStreams(expectedStreams, currentStreams))
            throw new IOException("The selected item's named data streams changed after review; refusing cleanup");
    }

    private static string HashNamedStreams(
        string path, List<FileStream> heldLocks, out List<NamedStreamSnapshot> streamSnapshot)
    {
        return HashNamedStreams(path, heldLocks, out streamSnapshot, null);
    }

    private static string HashNamedStreams(
        string path, List<FileStream> heldLocks, out List<NamedStreamSnapshot> streamSnapshot,
        Action<long, long> progressCallback)
    {
        List<NamedStreamSnapshot> streams = EnumerateNamedStreams(path);
        StringBuilder fingerprint = new StringBuilder();
        foreach (NamedStreamSnapshot namedStream in streams)
        {
            SafeFileHandle handle = Open(
                NamedStreamPath(path, namedStream.Name), GenericRead | ReadAttributes, ShareAll);
            FileStream stream = new FileStream(handle, FileAccess.Read, 131072, false);
            bool keepOpen = false;
            try
            {
                if (heldLocks != null) LockFileContents(stream.SafeFileHandle);
                FileInformation information = Information(stream.SafeFileHandle);
                if (FileSize(information) != namedStream.Length)
                    throw new IOException("A named data stream changed while it was being checked; refusing cleanup");

                stream.Position = 0;
                string contentHash;
                contentHash = HashFileStream(stream, progressCallback);
                if (stream.Length != namedStream.Length)
                    throw new IOException("A named data stream changed while it was being checked; refusing cleanup");

                fingerprint.Append(namedStream.Name.Length).Append(':')
                    .Append(namedStream.Name.ToUpperInvariant()).Append(':')
                    .Append(namedStream.Length).Append(':').Append(contentHash).Append('\n');
                if (heldLocks != null)
                {
                    heldLocks.Add(stream);
                    keepOpen = true;
                }
            }
            finally
            {
                if (!keepOpen) stream.Dispose();
            }
        }

        List<NamedStreamSnapshot> currentStreams = EnumerateNamedStreams(path);
        if (!SameNamedStreams(streams, currentStreams))
            throw new IOException("Named data streams changed while they were being checked; refusing cleanup");
        streamSnapshot = streams;
        using (SHA256 sha256 = SHA256.Create())
            return BitConverter.ToString(sha256.ComputeHash(Encoding.UTF8.GetBytes(fingerprint.ToString()))).Replace("-", "");
    }

    private static string FileContentHash(
        string path, FileStream defaultStream, List<FileStream> heldStreamLocks,
        out List<NamedStreamSnapshot> streamSnapshot)
    {
        return FileContentHash(path, defaultStream, heldStreamLocks, out streamSnapshot, null);
    }

    private static string FileContentHash(
        string path, FileStream defaultStream, List<FileStream> heldStreamLocks,
        out List<NamedStreamSnapshot> streamSnapshot, Action<long, long> progressCallback)
    {
        FileInformation information = Information(defaultStream.SafeFileHandle);
        string defaultHash = HashFileStream(defaultStream, progressCallback);

        string streamsHash = HashNamedStreams(
            path, heldStreamLocks, out streamSnapshot, progressCallback);
        if (streamSnapshot.Count == 0) return defaultHash;

        string material = FileSize(information).ToString(System.Globalization.CultureInfo.InvariantCulture) +
            ":" + defaultHash + ":" + streamsHash;
        using (SHA256 sha256 = SHA256.Create())
            return BitConverter.ToString(sha256.ComputeHash(Encoding.UTF8.GetBytes(material))).Replace("-", "");
    }

    private static string HashFileStream(FileStream stream, Action<long, long> progressCallback)
    {
        stream.Position = 0;
        long totalBytes = stream.Length;
        long processedBytes = 0;
        long lastReportedBytes = 0;
        System.Diagnostics.Stopwatch progressTimer = System.Diagnostics.Stopwatch.StartNew();
        byte[] buffer = new byte[1024 * 1024];
        using (SHA256 sha256 = SHA256.Create())
        {
            int bytesRead;
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha256.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                processedBytes += bytesRead;
                if (progressCallback != null &&
                    (processedBytes - lastReportedBytes >= 64L * 1024L * 1024L ||
                     progressTimer.ElapsedMilliseconds >= 10000 || processedBytes == totalBytes))
                {
                    progressCallback(processedBytes, totalBytes);
                    lastReportedBytes = processedBytes;
                    progressTimer.Restart();
                }
            }
            sha256.TransformFinalBlock(new byte[0], 0, 0);
            return BitConverter.ToString(sha256.Hash).Replace("-", "");
        }
    }

    private static long LastWriteFileTime(FileInformation information)
    {
        long high = unchecked((uint)information.LastWriteTime.dwHighDateTime);
        long low = unchecked((uint)information.LastWriteTime.dwLowDateTime);
        return (high << 32) | low;
    }

    private static void RequireFileSnapshot(
        FileInformation information, long expectedLength, long expectedLastWriteFileTime)
    {
        if (FileSize(information) != expectedLength ||
            LastWriteFileTime(information) != expectedLastWriteFileTime)
            throw new IOException("The selected file's size or last-modified time changed after its contents were checked; refusing cleanup");
    }

    private static List<SafeFileHandle> LockParentDirectories(string path)
    {
        string fullPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string root = Path.GetPathRoot(fullPath);
        if (String.IsNullOrEmpty(root))
            throw new IOException("Cleanup paths must be absolute local paths.");
        List<SafeFileHandle> parents = new List<SafeFileHandle>();
        try
        {
            SafeFileHandle rootHandle = Open(root, ReadAttributes);
            parents.Add(rootHandle);
            RequireOrdinaryType(Information(rootHandle), true);

            string relative = fullPath.Substring(root.Length);
            string[] parts = relative.Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
            string current = root;
            for (int index = 0; index < parts.Length - 1; index++)
            {
                current = Path.Combine(current, parts[index]);
                SafeFileHandle parent = Open(current, ReadAttributes);
                parents.Add(parent);
                RequireOrdinaryType(Information(parent), true);
            }
            return parents;
        }
        catch
        {
            for (int index = parents.Count - 1; index >= 0; index--)
                parents[index].Dispose();
            throw;
        }
    }

    private static void CheckParentDirectories(string path)
    {
        List<SafeFileHandle> parents = LockParentDirectories(path);
        try
        {
            // LockParentDirectories validates each path component while its
            // handle is open. This diagnostic check runs only after the
            // target identity changed, so it does not add work to normal files.
        }
        finally
        {
            for (int index = parents.Count - 1; index >= 0; index--)
                parents[index].Dispose();
        }
    }

    private static LockedPath OpenLockedPath(string path, bool isDirectory, uint targetAccess)
    {
        string fullPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string root = Path.GetPathRoot(fullPath);
        if (String.IsNullOrEmpty(root) || String.Equals(fullPath, root.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
            throw new IOException("Drive roots are not valid cleanup targets");

        LockedPath locked = new LockedPath();
        try
        {
            locked.Parents.AddRange(LockParentDirectories(fullPath));
            locked.Target = Open(fullPath, targetAccess);
            RequireOrdinaryType(Information(locked.Target), isDirectory);
            return locked;
        }
        catch
        {
            locked.Dispose();
            throw;
        }
    }

    private static void RequireIdentity(FileInformation information, string expectedIdentity)
    {
        if (!String.Equals(Identity(information), expectedIdentity, StringComparison.OrdinalIgnoreCase))
            throw new IOException("A cleanup path was replaced after review; refusing deletion");
    }

    private static void LockFileContents(SafeFileHandle handle)
    {
        // Share-lock the full range representable by .NET file offsets,
        // including future growth. This blocks writes while allowing readers.
        // A zeroed OVERLAPPED structure starts at byte zero; fail immediately
        // when another process holds a conflicting exclusive range.
        IntPtr overlapped = Marshal.AllocHGlobal(64);
        try
        {
            Marshal.Copy(new byte[64], 0, overlapped, 64);
            if (!LockFileEx(handle, 0x00000001, 0, 0xFFFFFFFF, 0x7FFFFFFF, overlapped))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 33)
                    throw new IOException("The selected file is in use; refusing cleanup");
                throw new Win32Exception(error, "Could not lock selected file contents for cleanup.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(overlapped);
        }
    }

    private static void MarkForDeletion(SafeFileHandle handle)
    {
        FileDisposition disposition = new FileDisposition();
        disposition.DeleteFile = true;
        if (!SetFileInformationByHandle(
                handle, FileDispositionInfo, ref disposition,
                (uint)Marshal.SizeOf(typeof(FileDisposition))))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows refused to remove the selected item.");
    }

    private static bool ClearReadOnly(SafeFileHandle handle)
    {
        FileBasicInformation information;
        uint informationSize = (uint)Marshal.SizeOf(typeof(FileBasicInformation));
        if (!GetFileInformationByHandleEx(handle, FileBasicInfo, out information, informationSize))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not inspect selected file attributes.");
        if ((information.Attributes & AttributeReadOnly) == 0) return false;
        information.Attributes &= ~AttributeReadOnly;
        if (information.Attributes == 0) information.Attributes = 0x00000080;
        if (!SetFileInformationByHandle(handle, FileBasicInfo, ref information, informationSize))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not clear the selected file's read-only attribute.");
        return true;
    }

    private static void RestoreReadOnly(SafeFileHandle handle)
    {
        FileBasicInformation information;
        uint informationSize = (uint)Marshal.SizeOf(typeof(FileBasicInformation));
        if (!GetFileInformationByHandleEx(handle, FileBasicInfo, out information, informationSize))
            throw new IOException("Windows refused removal, and the original read-only attribute could not be restored");
        information.Attributes |= AttributeReadOnly;
        if (!SetFileInformationByHandle(handle, FileBasicInfo, ref information, informationSize))
            throw new IOException("Windows refused removal, and the original read-only attribute could not be restored");
    }

    public static string GetIdentity(string path, bool isDirectory)
    {
        using (LockedPath locked = OpenLockedPath(path, isDirectory, ReadAttributes))
            return Identity(Information(locked.Target));
    }

    public static string GetDirectoryIdentityAndStreamsHash(string path)
    {
        return GetDirectoryIdentityAndStreamsHash(path, null);
    }

    public static string GetDirectoryIdentityAndStreamsHash(
        string path, Action<long, long> progressCallback)
    {
        using (LockedPath locked = OpenLockedPath(path, true, ReadAttributes))
        {
            List<NamedStreamSnapshot> streams;
            string streamsHash = HashNamedStreams(path, null, out streams, progressCallback);
            return Identity(Information(locked.Target)) + "|" + streamsHash;
        }
    }

    public static string GetFileIdentityAndHash(string path)
    {
        return GetFileIdentityAndHash(path, null);
    }

    public static string GetFileIdentityAndHash(string path, Action<long, long> progressCallback)
    {
        using (SafeFileHandle handle = Open(path, GenericRead | ReadAttributes))
        {
            FileInformation information = Information(handle);
            RequireOrdinaryType(information, false);
            FileStream stream = new FileStream(handle, FileAccess.Read, 131072, false);
            using (stream)
            {
                List<NamedStreamSnapshot> streams;
                string hash = FileContentHash(path, stream, null, out streams, progressCallback);
                return Identity(information) + "|" + hash;
            }
        }
    }

    public static void DeleteFileIfUnchanged(
        string path, string expectedIdentity, string expectedHash,
        long expectedLength, long expectedLastWriteFileTime)
    {
        DeleteFileIfUnchanged(
            path, expectedIdentity, expectedHash, expectedLength,
            expectedLastWriteFileTime, null);
    }

    public static void DeleteFileIfUnchanged(
        string path, string expectedIdentity, string expectedHash,
        long expectedLength, long expectedLastWriteFileTime,
        Action<long, long> progressCallback)
    {
        SafeFileHandle handle = Open(path, DeleteAccess | GenericRead | ReadAttributes | WriteAttributes);
        FileInformation openedInformation;
        try
        {
            openedInformation = Information(handle);
            RequireOrdinaryType(openedInformation, false);
            try
            {
                RequireIdentity(openedInformation, expectedIdentity);
            }
            catch (IOException)
            {
                // A junction can redirect this first open to a different file.
                // Identify that case before reporting a generic identity change.
                CheckParentDirectories(path);
                throw;
            }
            RequireFileSnapshot(openedInformation, expectedLength, expectedLastWriteFileTime);
        }
        catch
        {
            handle.Dispose();
            throw;
        }

        FileStream stream = new FileStream(handle, FileAccess.Read, 131072, false);
        List<FileStream> namedStreamLocks = new List<FileStream>();
        try
        {
            using (stream)
            {
                LockFileContents(stream.SafeFileHandle);
                FileInformation lockedInformation = Information(stream.SafeFileHandle);
                RequireOrdinaryType(lockedInformation, false);
                RequireIdentity(lockedInformation, expectedIdentity);
                RequireFileSnapshot(lockedInformation, expectedLength, expectedLastWriteFileTime);
                List<NamedStreamSnapshot> namedStreamSnapshot;
                string currentHash = FileContentHash(
                    path, stream, namedStreamLocks, out namedStreamSnapshot, progressCallback);
                if (!String.Equals(currentHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("The selected file's contents changed after backup verification; refusing cleanup");

                List<SafeFileHandle> parentLocks = LockParentDirectories(path);
                try
                {
                    using (SafeFileHandle pathHandle = Open(path, ReadAttributes, ShareAll))
                    {
                        FileInformation currentInformation = Information(pathHandle);
                        RequireOrdinaryType(currentInformation, false);
                        RequireIdentity(currentInformation, expectedIdentity);
                        RequireFileSnapshot(currentInformation, expectedLength, expectedLastWriteFileTime);
                    }
                    RequireNamedStreamsUnchanged(path, namedStreamSnapshot);
                    bool readOnlyCleared = ClearReadOnly(stream.SafeFileHandle);
                    try
                    {
                        MarkForDeletion(stream.SafeFileHandle);
                    }
                    catch
                    {
                        if (readOnlyCleared) RestoreReadOnly(stream.SafeFileHandle);
                        throw;
                    }
                }
                finally
                {
                    for (int index = parentLocks.Count - 1; index >= 0; index--)
                        parentLocks[index].Dispose();
                }
            }
        }
        finally
        {
            for (int index = namedStreamLocks.Count - 1; index >= 0; index--)
                namedStreamLocks[index].Dispose();
        }
    }

    public static void DeleteEmptyDirectoryIfUnchanged(
        string path, string expectedIdentity, string expectedStreamsHash)
    {
        DeleteEmptyDirectoryIfUnchanged(path, expectedIdentity, expectedStreamsHash, null);
    }

    public static void DeleteEmptyDirectoryIfUnchanged(
        string path, string expectedIdentity, string expectedStreamsHash,
        Action<long, long> progressCallback)
    {
        using (LockedPath locked = OpenLockedPath(
                path, true, DeleteAccess | ReadAttributes))
        {
            RequireIdentity(Information(locked.Target), expectedIdentity);
            List<FileStream> namedStreamLocks = new List<FileStream>();
            try
            {
                List<NamedStreamSnapshot> namedStreamSnapshot;
                string currentStreamsHash = HashNamedStreams(
                    path, namedStreamLocks, out namedStreamSnapshot, progressCallback);
                if (!String.Equals(currentStreamsHash, expectedStreamsHash, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("The selected item's named data streams changed after review; refusing cleanup");
                RequireNamedStreamsUnchanged(path, namedStreamSnapshot);
                MarkForDeletion(locked.Target);
            }
            finally
            {
                for (int index = namedStreamLocks.Count - 1; index >= 0; index--)
                    namedStreamLocks[index].Dispose();
            }
        }
    }
}
"""

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="backslashreplace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(errors="backslashreplace")

# Patterns used to identify potential cleanup candidates.
CLEANABLE_PATTERNS = {
    "high": {
        "name": "High Priority (Lower Risk)",
        "patterns": [
            {"pattern": "\\pip\\cache", "name": "pip cache", "safe": True},
            {"pattern": "\\.cache\\puppeteer", "name": "Puppeteer cache", "safe": True},
            {"pattern": "\\electron\\cache", "name": "Electron cache", "safe": True},
            {"pattern": "\\npm-cache", "name": "npm cache", "safe": True},
            {"pattern": "\\yarn\\cache", "name": "Yarn cache", "safe": True},
            {"pattern": "temp", "known_temp_location": True, "name": "Temporary files (check for installers or builds in progress)", "safe": True},
            {"pattern": "tmp", "known_temp_location": True, "name": "Temporary files (check for installers or builds in progress)", "safe": True},
        ]
    },
    "medium": {
        "name": "Medium Priority (Use Caution)",
        "patterns": [
            {"pattern": "livekernelreports", "root": "windows", "root_child": True, "name": "Windows crash diagnostics (keep if troubleshooting; may contain memory data)", "safe": False},
            {"pattern": "crashdump", "root": "windows", "root_child": True, "name": "Windows crash diagnostics (keep if troubleshooting; may contain memory data)", "safe": False},
            {"pattern": "crashdumps", "root": "windows", "root_child": True, "name": "Windows crash diagnostics (keep if troubleshooting; may contain memory data)", "safe": False},
            {"pattern": "crashdump.dmp", "root": "windows", "root_child": True, "name": "Windows crash dump file (keep if troubleshooting; may contain memory data)", "safe": False},
            {"pattern": "minidump.dmp", "root": "windows", "root_child": True, "name": "Windows crash dump file (keep if troubleshooting; may contain memory data)", "safe": False},
            {"pattern": "memory.dmp", "root": "windows", "root_child": True, "name": "Windows memory dump (may contain memory data; keep if troubleshooting)", "safe": False},
            {"pattern": "minidump", "root": "windows", "root_child": True, "name": "Windows crash diagnostics (keep if troubleshooting; may contain memory data)", "safe": False},
            {"pattern": "\\temp\\chocolatey", "known_temp_location": True, "component_match_required": True, "name": "Chocolatey package staging (confirm installs are complete and review contents)", "safe": False},
            {"pattern": "cargo-install", "component_prefix": True, "component_prefix_requires_suffix": True, "known_temp_location": True, "component_match_required": True, "name": "Cargo install build output (confirm the install completed and review its compiled files)", "safe": False},
            {"pattern": "\\chrome\\user data\\optguideondevicemodel", "name": "Chrome on-device AI model (close Chrome first; it may be downloaded again; consider disabling optimization-guide-on-device-model in chrome://flags)", "safe": False},
            {"pattern": "\\cache\\", "name": "Cache-named data (inspect its location and contents; the name alone does not prove it is disposable)", "safe": False},
            {"pattern": "\\caches\\", "name": "Cache-named data (inspect its location and contents; the name alone does not prove it is disposable)", "safe": False},
            {"pattern": "\\appdata\\roaming\\code\\cachedextensionvsixs", "name": "VS Code cached extensions (close VS Code first; may be useful for offline reinstalls)", "safe": False},
            {"pattern": "\\appdata\\roaming\\code\\cacheddata", "name": "VS Code cache (close VS Code first; review exact contents)", "safe": False},
            {"pattern": "\\appdata\\roaming\\code\\cache", "name": "VS Code cache (close VS Code first; review exact contents)", "safe": False},
            {"pattern": "\\appdata\\roaming\\code\\crashpad", "name": "VS Code crash reports (keep while troubleshooting; review before cleanup)", "safe": False},
            {"pattern": "\\logs\\", "name": "Logs data (review contents; may include user or diagnostic history)", "safe": False},
            {"pattern": "gpucache", "name": "GPU cache data (review which application owns it before cleanup)", "safe": False},
            {"pattern": "shadercache", "name": "Shader cache data (review which application owns it before cleanup)", "safe": False},
            {"pattern": "code cache", "name": "Code cache data (review which application owns it before cleanup)", "safe": False},
            {"pattern": "temp", "unknown_temp_location": True, "name": "Folder named Temp (inspect its owner and contents; the name alone does not prove it is temporary)", "safe": False},
            {"pattern": "tmp", "unknown_temp_location": True, "name": "Folder named Tmp (inspect its owner and contents; the name alone does not prove it is temporary)", "safe": False},
        ]
    },
    "low": {
        "name": "Low Priority (Confirm First)",
        "patterns": [
            {"pattern": "\\.gradle\\caches", "name": "Gradle cache", "safe": False},
            {"pattern": "\\.cargo\\registry", "name": "Cargo cache", "safe": False},
            {"pattern": "\\.nuget\\packages", "name": "NuGet cache", "safe": False},
            {"pattern": "\\go\\pkg\\mod", "name": "Go modules cache", "safe": False},
            {"pattern": "\\scoop\\cache", "name": "Scoop downloaded installers (may be needed for offline reinstall; prefer Scoop cache management)", "safe": False},
            {"pattern": "\\programdata\\nvidia corporation\\nvidia app\\updateframework\\ota-artifacts", "name": "NVIDIA App driver-update files (confirm no download or installation is active; may be needed to retry an update)", "safe": False},
            {"pattern": "\\programdata\\nvidia corporation\\nvapp-updateframework\\ota-artifacts", "name": "NVIDIA App driver-update files (confirm no download or installation is active; may be needed to retry an update)", "safe": False},
            {"pattern": "\\ms-playwright", "name": "Playwright test browsers (can be reinstalled with `npx playwright install`)", "safe": False},
            {"pattern": "indexeddb", "browser_profile": True, "name": "Chrome/Edge profile IndexedDB data (offline web-app data or login state; deleting it can sign you out or lose data)", "safe": False},
        ]
    }
}

# Safety exclusions: never recommend these paths for cleanup.
EXCLUDE_PATTERNS = [
    # Critical Windows data
    "\\windows\\winsxs",
    "\\windows\\system32",
    "\\windows\\syswow64",
    "\\windows\\installer",              # Repair/uninstall data for installed software
    "\\program files\\",
    "\\program files (x86)\\",
    "\\programdata\\microsoft\\windows\\",
    "\\windows\\softwaredistribution\\download\\", # Use Windows maintenance tools for update downloads
    "\\$mft",                            # NTFS file-system metadata
    "\\$extend",                         # NTFS file-system metadata
    "pagefile.sys",                      # Windows virtual memory file
    "swapfile.sys",                      # Windows virtual memory file
    "hiberfil.sys",                      # Windows hibernation file
    "system volume information",         # System restore points
    "\\driverstore\\",                   # Active driver store
    "$recycle.bin",
    # Installer repair caches
    "package cache",
    "installercache",
    # Personal data
    "\\documents\\",
    "\\desktop\\",
    "\\pictures\\",
    "\\videos\\",
    "\\music\\",
    "\\downloads\\",                   # May contain projects, installers, and user files
    "\\contacts\\",
    "\\favorites\\",
    "\\links\\",
    "\\saved games\\",
    "\\saved pictures\\",
    "\\camera roll\\",
    "\\searches\\",
    "\\3d objects\\",
    "\\recovered-windowsold\\",         # Preserve data retained from a previous Windows installation
    "\\$winreagent",                      # Windows-managed update recovery staging
    "\\programdata\\usoshared\\logs\\", # Active Windows Update diagnostics
    "\\service worker\\",               # May contain offline site data and user state
    ".vscode",                         # VS Code extension storage and workspace data
    "\\.codex\\",                       # Codex settings, extensions, and task data
    "\\.codex-old\\",                   # Legacy Codex profile may contain authentication and task state
    "\\.agents\\",                      # User-installed agent skills and configuration
    "\\.claude\\",                      # Agent settings, history, and local state
    "\\.cursor\\",                      # Editor and agent settings and local state
    "\\.gemini\\",                      # Agent settings and authentication state
    "\\.github\\",                      # Project and account configuration
    "\\.opencode\\",                    # Agent settings and local state
    "\\.windsurf\\",                    # Editor and agent settings and local state
    "\\appdata\\local\\packages\\", # Store app data managed by the app and Windows
    "\\appdata\\roaming\\codex\\",    # Codex app state and browser profile data
    "\\.local\\share\\containers\\",  # Container or Podman machine state
    "\\onedrive",
    "tencent files",                     # Files received through QQ
    "xwechat_files",                     # WeChat files
    "wechat files",
    # Credentials and application settings
    "\\.ssh\\",
    "\\.gnupg\\",
    # Cloud, container, and source-control CLI profiles can store credentials.
    "\\.aws\\",
    "\\.azure\\",
    "\\.kube\\",
    "\\.docker\\",
    "\\.config\\gcloud\\",
    "\\.config\\gh\\",
]
EXCLUDE_COMPONENT_PREFIXES = ("onedrive - ", "openai.codex_")

ANALYSIS_PROGRESS_INTERVAL = 100_000
MANUAL_REVIEW_FILE_LIMIT = 100
MANUAL_REVIEW_HEAP_LIMIT = 500
MANUAL_REVIEW_PAGE_SIZE = 25
MANUAL_REVIEW_LABEL = "Large file (manual review required)"
PROJECT_MARKERS = (
    ".drive-cleanr-protect", ".git", ".gitignore", ".gitattributes", ".editorconfig",
    ".hg", ".svn", ".idea", ".vscode", ".vs", ".cursorrules",
    ".claude", ".cursor", ".gemini", ".github", ".opencode", ".windsurf",
    "agents.md", "agents.override.md", "claude.md", "gemini.md",
    "copilot-instructions.md", "skill.md",
    "pyproject.toml", "package.json", "cargo.toml",
    "go.mod", "go.work", "cmakelists.txt", "cmakepresets.json", "makefile", "meson.build",
    "build.ninja", "setup.py", "setup.cfg", "requirements.txt", "pipfile", "pipfile.lock",
    "poetry.lock", "uv.lock", "tox.ini", "pytest.ini", "environment.yml", "environment.yaml",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "deno.json",
    "deno.jsonc", "cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    "settings.gradle.kts", "gradlew", "gradlew.bat", "composer.json", "composer.lock", "gemfile",
    "gemfile.lock", "rakefile", "dockerfile", "containerfile", "docker-compose.yml",
    "docker-compose.yaml", "build.sbt", "mix.exs", "pubspec.yaml", "project.godot", "projectsettings",
)
PROJECT_MARKER_SUFFIXES = (
    ".sln", ".slnx", ".csproj", ".vbproj", ".fsproj", ".vcxproj", ".wixproj",
    ".uproject", ".uplugin", ".code-workspace", "-requirements.txt",
)
_PROJECT_MARKER_NAMES = frozenset(marker.casefold() for marker in PROJECT_MARKERS)
_PROFILE_ROOT_IGNORED_MARKERS = frozenset({
    ".editorconfig", ".vscode",
    ".cursorrules", ".claude", ".cursor", ".gemini", ".github", ".opencode", ".windsurf",
    "agents.md", "agents.override.md", "claude.md", "gemini.md",
    "copilot-instructions.md", "skill.md",
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "bun.lock",
    "bun.lockb", "pnpm-lock.yaml", "yarn.lock",
})
WINDOWS_RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
    *(f"COM{digit}" for digit in "¹²³"),
    *(f"LPT{digit}" for digit in "¹²³"),
})
_BROWSER_PROFILE_MARKERS = (
    ("chrome", "user data"),
    ("edge", "user data"),
)
INVALID_WINDOWS_PATH_CHARACTERS = re.compile(r'[<>:"|?*\x00-\x1f]')


def format_size(size_bytes):
    """Format a byte count for display."""
    if size_bytes >= 1024 ** 3:
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    elif size_bytes >= 1024 ** 2:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    return f"{size_bytes} B"


def _scan_mode_from_filename(csv_path):
    """Read scan-mode hints encoded by Drive Cleanr without altering scanner CSVs."""
    name = Path(csv_path).name.casefold()
    if name.startswith("scan_wiztree_standard_"):
        return "wiztree_standard"
    if name.startswith("scan_wiztree_fast_"):
        return "wiztree_fast"
    if name.startswith("scan_windirstat_"):
        return "windirstat"
    return None


def _scan_file_timestamp(csv_path):
    """Return the export's last-modified time, or None if metadata is unavailable."""
    try:
        modified = os.path.getmtime(csv_path)
        return datetime.fromtimestamp(modified).astimezone().isoformat(timespec="seconds")
    except (OSError, OverflowError, ValueError):
        return None


def _safe_scan_timestamp(results):
    """Normalize scan timestamp metadata before embedding it in generated text."""
    value = results.get("scan_file_time")
    if not isinstance(value, str):
        return "Unknown"
    try:
        return datetime.fromisoformat(value).isoformat(timespec="seconds")
    except ValueError:
        return "Unknown"


def classify_path(path):
    """Classify a scan row as a file or directory from its path."""
    if path.endswith("\\") or path.endswith("/"):
        return "Directory"
    return "File"


def _is_directory_row(fields):
    """Return a WinDirStat row type, or None when its type is ambiguous."""
    attributes = str(fields.get('attributes') or '').casefold()
    windirstat_attributes = str(fields.get('windirstatattributes') or '')
    try:
        windirstat_type = int(windirstat_attributes, 0) & 0xF
    except (TypeError, ValueError):
        windirstat_type = None
    try:
        has_children = int(fields.get('files') or 0) > 0 or int(fields.get('folders') or 0) > 0
    except (TypeError, ValueError):
        has_children = False
    if windirstat_type == 0x4 or 'directory' in attributes or any(
            token == 'd' for token in re.findall(r'[a-z]+', attributes)) or has_children:
        return 'directory'
    if windirstat_type == 0x8:
        return 'file'
    return None


def _is_under(child, parent):
    """Windows-aware path containment, including case and trailing separators."""
    child_key = _path_key(child)
    parent_key = _path_key(parent)
    return child_key != parent_key and child_key.startswith(parent_key.rstrip("\\") + "\\")


def _path_key(path):
    return ntpath.normcase(ntpath.normpath(path.replace("/", "\\")))


def _path_has_reparse_component_cached(path, cache):
    """Check path components for links while reusing unchanged ancestors."""
    absolute = os.path.abspath(os.fspath(path))
    drive, tail = os.path.splitdrive(absolute)
    current = drive + os.sep if drive else os.path.abspath(os.sep)
    for part in tail.strip("\\/").replace("/", os.sep).split(os.sep):
        if not part:
            continue
        current = os.path.join(current, part)
        key = _path_key(current)
        if key not in cache:
            cache[key] = scan._is_reparse_point(current)
        if cache[key]:
            return True
    return False


def _path_components(path, drive_tail=None):
    """Return case-insensitive Windows path components without drive/root syntax."""
    if drive_tail is None:
        normalized = str(path).replace("/", "\\").casefold()
        _drive, drive_tail = ntpath.splitdrive(normalized)
    else:
        drive_tail = drive_tail.casefold()
    return [part for part in drive_tail.split("\\") if part]


@lru_cache(maxsize=32)
def _configured_temp_root_components(temp, tmp, local_app_data, windows_dir, system_root, default_temp):
    roots = [temp, tmp, default_temp]
    if local_app_data:
        roots.append(ntpath.join(local_app_data, "Temp"))
    windows_dir = windows_dir or system_root
    if windows_dir:
        roots.extend((ntpath.join(windows_dir, "Temp"), ntpath.join(windows_dir, "SystemTemp")))
    else:
        roots.extend((r"C:\Windows\Temp", r"C:\Windows\SystemTemp"))

    result = []
    for root in roots:
        if not root:
            continue
        normalized_root = str(root).replace("/", "\\")
        drive, tail = ntpath.splitdrive(normalized_root)
        if not drive or not tail.startswith("\\"):
            continue
        result.append((drive.casefold(), tuple(_path_components(normalized_root, tail))))
    return tuple(result)


def _current_temp_root_components():
    return _configured_temp_root_components(
        os.environ.get("TEMP"), os.environ.get("TMP"),
        os.environ.get("LOCALAPPDATA"), os.environ.get("WINDIR"),
        os.environ.get("SystemRoot"), tempfile.gettempdir(),
    )


_EXCLUDE_COMPONENTS = tuple(tuple(_path_components(pattern)) for pattern in EXCLUDE_PATTERNS)
_CLEANABLE_COMPONENTS = {
    priority: tuple((pattern_info, tuple(_path_components(pattern_info["pattern"])))
                    for pattern_info in category["patterns"])
    for priority, category in CLEANABLE_PATTERNS.items()
}
_CLEANUP_TIE_BREAK_RANK = {"low": 0, "medium": 1, "high": 2}
_CLEANABLE_RULES = tuple(sorted(
    ((priority, pattern_info, pattern_components)
     for priority, patterns in _CLEANABLE_COMPONENTS.items()
     for pattern_info, pattern_components in patterns),
    # Prefer the more cautious tier when equally specific rules overlap. A
    # broad Temp match must not hide a caution label such as Cache or Logs.
    key=lambda rule: (-len(rule[2]), _CLEANUP_TIE_BREAK_RANK[rule[0]]),
))
_CLEANUP_RULES_BY_COMPONENT = {}
_CLEANUP_RULES_BY_SEQUENCE = {}
_CLEANUP_PREFIX_RULES = []
for _rule_index, (_priority, _pattern_info, _pattern_components) in enumerate(_CLEANABLE_RULES):
    if _pattern_info.get("component_prefix"):
        _CLEANUP_PREFIX_RULES.append((
            _rule_index,
            _pattern_components[-1],
            bool(_pattern_info.get("component_prefix_requires_suffix")),
        ))
    elif len(_pattern_components) == 1:
        _CLEANUP_RULES_BY_COMPONENT.setdefault(_pattern_components[0], []).append(_rule_index)
    else:
        _CLEANUP_RULES_BY_SEQUENCE.setdefault(_pattern_components, []).append(_rule_index)
_CLEANUP_RULES_BY_COMPONENT = {
    component: tuple(indices)
    for component, indices in _CLEANUP_RULES_BY_COMPONENT.items()
}
_CLEANUP_RULES_BY_SEQUENCE = {
    sequence: tuple(indices)
    for sequence, indices in _CLEANUP_RULES_BY_SEQUENCE.items()
}
_CLEANUP_PREFIX_RULES = tuple(_CLEANUP_PREFIX_RULES)
_CLEANUP_KNOWN_TEMP_CATCHALL_RULES = tuple(
    index for index, (_priority, info, _components) in enumerate(_CLEANABLE_RULES)
    if info.get("known_temp_location") and not info.get("component_match_required")
)
_EXCLUDE_SINGLE_COMPONENTS = frozenset(
    pattern[0] for pattern in _EXCLUDE_COMPONENTS if len(pattern) == 1
)
_EXCLUDE_SEQUENCES = {
    length: frozenset(pattern for pattern in _EXCLUDE_COMPONENTS if len(pattern) == length)
    for length in {len(pattern) for pattern in _EXCLUDE_COMPONENTS if len(pattern) > 1}
}
_COMPONENT_SEQUENCE_LENGTHS = frozenset(
    {len(pattern) for pattern in _EXCLUDE_COMPONENTS if len(pattern) > 1}
    | {len(pattern) for patterns in _CLEANABLE_COMPONENTS.values()
       for _, pattern in patterns if len(pattern) > 1}
)


def _path_match_index(components):
    """Build reusable set indexes for all exact and adjacent path rules."""
    component_set = set(components)
    sequences = {
        length: {
            tuple(components[index:index + length])
            for index in range(len(components) - length + 1)
        }
        for length in _COMPONENT_SEQUENCE_LENGTHS if len(components) >= length
    }
    return component_set, sequences


def _candidate_cleanup_rules(path, components, component_set, sequences,
                             known_temp_location=None):
    """Return only rules whose exact path components could match this path."""
    if known_temp_location is None:
        known_temp_location = _is_known_temp_location(path, components)
    candidate_indices = set()
    for component in component_set:
        candidate_indices.update(_CLEANUP_RULES_BY_COMPONENT.get(component, ()))
    for path_sequences in sequences.values():
        for path_sequence in path_sequences:
            candidate_indices.update(_CLEANUP_RULES_BY_SEQUENCE.get(path_sequence, ()))
    for index, prefix, requires_suffix in _CLEANUP_PREFIX_RULES:
        if any(
                component.startswith(prefix) and
                (not requires_suffix or len(component) > len(prefix))
                for component in components):
            candidate_indices.add(index)
    if known_temp_location:
        candidate_indices.update(_CLEANUP_KNOWN_TEMP_CATCHALL_RULES)
    return (_CLEANABLE_RULES[index] for index in sorted(candidate_indices))


def _is_excluded_path(path, components=None, component_set=None, sequences=None):
    """Return whether a path matches a protected-path fragment."""
    components = components if components is not None else _path_components(path)
    if component_set is None or sequences is None:
        component_set, sequences = _path_match_index(components)
    if not _EXCLUDE_SINGLE_COMPONENTS.isdisjoint(component_set):
        return True
    if any(not excluded.isdisjoint(sequences.get(length, ()))
           for length, excluded in _EXCLUDE_SEQUENCES.items()):
        return True
    return any(component.startswith(prefix)
               for component in components for prefix in EXCLUDE_COMPONENT_PREFIXES)


def _cleanup_rule_matches(pattern_info, pattern_components, components, component_set,
                          sequences, path=None, known_temp_location=None):
    """Match a rule's component pattern and any required path-root prefix."""
    root = pattern_info.get("root")
    if root:
        root_components = tuple(_path_components(root))
        if tuple(components[:len(root_components)]) != root_components:
            return False
    else:
        root_components = ()
    if pattern_info.get("root_child"):
        # Diagnostic rules can require a known directory/file directly under
        # the Windows root instead of matching similarly named user subtrees.
        required_prefix = root_components + pattern_components
        if tuple(components[:len(required_prefix)]) != required_prefix:
            return False
    component_match = (
        (len(pattern_components) == 1 and pattern_components[0] in component_set) or
        (len(pattern_components) > 1 and
         pattern_components in sequences.get(len(pattern_components), ()))
    )
    if pattern_info.get("component_prefix"):
        prefix = pattern_components[-1]
        prefix_match = any(
            component.startswith(prefix) and (
                not pattern_info.get("component_prefix_requires_suffix") or
                len(component) > len(prefix)
            )
            for component in components
        )
        if pattern_info.get("component_prefix_requires_suffix"):
            component_match = prefix_match
        else:
            component_match = component_match or prefix_match
    if pattern_info.get("known_temp_location") or pattern_info.get("unknown_temp_location"):
        if known_temp_location is None:
            known_temp_location = _is_known_temp_location(path, components)
    if pattern_info.get("known_temp_location"):
        if not known_temp_location:
            return False
        if pattern_info.get("component_match_required") and not component_match:
            return False
    elif pattern_info.get("unknown_temp_location"):
        if not component_match or known_temp_location:
            return False
    elif not component_match:
        return False
    if pattern_info.get("browser_profile"):
        indexeddb_index = components.index("indexeddb")
        prefix = components[:indexeddb_index]
        if not any(
                any(tuple(prefix[index:index + len(marker)]) == marker
                    for index in range(len(prefix) - len(marker) + 1))
                for marker in _BROWSER_PROFILE_MARKERS):
            return False
    return True


def _is_known_temp_location(path, components):
    """Recognize Windows temp roots and explicitly configured TEMP/TMP paths."""
    if any(
            tuple(components[:len(root)]) == root
            for root in (
                ("windows", "temp"),
                ("windows", "systemtemp"),
            )
    ):
        return True
    if len(components) >= 5 and components[0] in {"users", "documents and settings"}:
        if components[2:5] == ["appdata", "local", "temp"]:
            return True

    drive = ntpath.splitdrive(str(path).replace("/", "\\"))[0].casefold()
    return any(
        drive == root_drive and len(components) >= len(root_components) and
        tuple(components[:len(root_components)]) == root_components
        for root_drive, root_components in _current_temp_root_components()
    )


def _is_known_temp_root(path, components=None):
    """Recognize the root of a configured or standard temporary folder."""
    components = components if components is not None else _path_components(path)
    if not _is_known_temp_location(path, components):
        return False
    parent = ntpath.dirname(str(path).rstrip("\\/"))
    return bool(parent and not _is_known_temp_location(parent, _path_components(parent)))


def _matches_cleanup_rule(path, priorities, name):
    """Require the analyzer's most-specific cleanup rule, priority, and label."""
    components = _path_components(path)
    component_set, sequences = _path_match_index(components)
    known_temp_location = _is_known_temp_location(path, components)
    known_temp_root = None
    for priority, pattern_info, pattern_components in _candidate_cleanup_rules(
            path, components, component_set, sequences, known_temp_location):
        if (pattern_info.get("known_temp_location") and
                (known_temp_root if known_temp_root is not None else
                 _is_known_temp_root(path, components))):
            known_temp_root = True
            continue
        if pattern_info.get("known_temp_location") and known_temp_root is None:
            known_temp_root = False
        if _cleanup_rule_matches(
                pattern_info, pattern_components, components, component_set,
                sequences, path=path, known_temp_location=known_temp_location):
            return priority in priorities and pattern_info["name"] == name
    return False


def _matches_any_cleanup_rule(path):
    """Return whether a path is covered by any automatic cleanup rule."""
    components = _path_components(path)
    component_set, sequences = _path_match_index(components)
    known_temp_location = _is_known_temp_location(path, components)
    known_temp_root = None
    for _priority, pattern_info, pattern_components in _candidate_cleanup_rules(
            path, components, component_set, sequences, known_temp_location):
        if (pattern_info.get("known_temp_location") and
                (known_temp_root if known_temp_root is not None else
                 _is_known_temp_root(path, components))):
            known_temp_root = True
            continue
        if pattern_info.get("known_temp_location") and known_temp_root is None:
            known_temp_root = False
        if _cleanup_rule_matches(
                pattern_info, pattern_components, components, component_set,
                sequences, path=path, known_temp_location=known_temp_location):
            return True
    return False


def _inside_project_tree(path, directory, cache, detected_projects=None):
    """Recognize project roots above a candidate to avoid recursive project cleanup."""
    normalized = ntpath.normpath(path.replace("/", "\\"))
    current = normalized if directory else ntpath.dirname(normalized)
    visited = []
    project_found = False
    while current:
        key = _path_key(current)
        if key in cache:
            project_found = cache[key]
            break
        _, tail = ntpath.splitdrive(current)
        top_level = [part for part in tail.strip("\\").split("\\") if part]
        visited.append(key)
        marker = []
        has_marker = (
            _directory_has_project_marker(current, marker)
            if detected_projects is not None
            else _directory_has_project_marker(current)
        )
        if has_marker:
            project_found = True
            if detected_projects is not None and marker:
                detected_projects.setdefault(
                    key, {"path": current, "marker": marker[0]}
                )
            break
        if (len(top_level) <= 2 and top_level and
                top_level[0].casefold() in {"users", "documents and settings"}):
            break
        parent = ntpath.dirname(current)
        if parent == current:
            break
        current = parent
    for key in visited:
        cache[key] = project_found
    return project_found


def _directory_has_project_marker(directory, marker_out=None):
    """Check common exact project markers and Windows project-file suffixes."""
    _, tail = ntpath.splitdrive(str(directory).replace("/", "\\"))
    parts = [part for part in tail.strip("\\").split("\\") if part]
    is_profile_root = (len(parts) == 2 and
                       parts[0].casefold() in {"users", "documents and settings"})
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                name = entry.name.casefold()
                # Developer tools place shared metadata and VS Code extensions
                # directly in a user profile. Treating those as a project root
                # would hide every otherwise eligible cleanup location there.
                if (is_profile_root and
                        (name in _PROFILE_ROOT_IGNORED_MARKERS or
                         name.endswith(".code-workspace"))):
                    continue
                if name in _PROJECT_MARKER_NAMES:
                    if marker_out is not None:
                        marker_out.append(entry.name)
                    return True
                if (entry.is_file(follow_symlinks=False) and
                        name.endswith(PROJECT_MARKER_SUFFIXES)):
                    if marker_out is not None:
                        marker_out.append(entry.name)
                    return True
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        # If a directory cannot be inspected for project markers, leave its
        # contents out of cleanup recommendations until it can be checked.
        return True
    return False


def _is_local_drive_path(path, drive=None, drive_tail=None):
    """Accept only normalized, non-root local Windows paths from scan exports."""
    if not isinstance(path, str) or not path or not path.isprintable():
        return False
    normalized = path.replace("/", "\\")
    if drive is None or drive_tail is None:
        drive, drive_tail = ntpath.splitdrive(normalized)
    if (len(drive) != 2 or not drive[0].isalpha() or drive[1] != ":" or
            not drive_tail.startswith("\\") or drive_tail.startswith("\\\\") or
            normalized.startswith("\\\\")):
        return False
    stripped_tail = drive_tail.strip("\\")
    if not stripped_tail:
        return False
    parts = stripped_tail.split("\\")
    if INVALID_WINDOWS_PATH_CHARACTERS.search(drive_tail):
        return False
    for part in parts:
        if (not part or part in {".", ".."} or part.endswith((".", " ")) or
                part.split(".")[0].rstrip(" .").upper() in WINDOWS_RESERVED_NAMES):
            return False
    return True


def _ps_literal(value):
    """Encode untrusted data as a PowerShell single-quoted string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def _ensure_output_outside_targets(output_path, items):
    """Do not place a generated report where a selected cleanup would remove it."""
    destination = _path_key(os.path.abspath(os.fspath(output_path)))
    for item in items:
        target = item.get("path")
        if isinstance(target, str) and (
                destination == _path_key(target) or _is_under(destination, target)):
            raise ValueError("Choose an output path outside the selected cleanup targets")


def _non_overlapping_items(items):
    """Keep the outermost candidate paths so parent/child sizes are not added."""
    ordered = sorted(items, key=lambda item: (item["path"].count("\\") + item["path"].count("/"), -item["size"]))
    selected = []
    for item in ordered:
        if any(_path_key(item["path"]) == _path_key(parent["path"]) or
               _is_under(item["path"], parent["path"]) for parent in selected):
            continue
        selected.append(item)
    return selected


def _nested_candidate_pairs(items):
    """Return each nested candidate with its nearest listed parent candidate."""
    pairs = []
    for child in items:
        parents = [
            candidate for candidate in items
            if candidate is not child and _is_under(child["path"], candidate["path"])
        ]
        if parents:
            parent = max(
                parents,
                key=lambda item: item["path"].count("\\") + item["path"].count("/"),
            )
            pairs.append((parent, child))
    return sorted(
        pairs,
        key=lambda pair: (
            pair[1]["path"].count("\\") + pair[1]["path"].count("/"),
            _path_key(pair[1]["path"]),
        ),
    )


def _nested_candidate_summary(items, pairs=None, pair_limit=5):
    """Explain candidate entries whose folder sizes are included in a parent."""
    if pairs is None:
        pairs = _nested_candidate_pairs(items)
    if not pairs:
        return []

    lines = [
        "Some listed items are inside a listed folder. Each row is shown separately, but the same space is counted only once in the total."
    ]
    for parent, child in pairs[:pair_limit]:
        lines.append(
            f"  {child['size_formatted']} at {child['path']} is inside "
            f"{parent['size_formatted']} at {parent['path']}"
        )
    if len(pairs) > pair_limit:
        lines.append(f"  ... and {len(pairs) - pair_limit} more listed file/folder pairs")
    return lines


def _tier_size_estimates(categories, nested_pairs=None):
    """Attribute nested candidate space to the most-specific candidate tier."""
    items = []
    priority_by_id = {}
    for priority, category in categories.items():
        for item in category["items"]:
            items.append(item)
            priority_by_id[id(item)] = priority

    estimates = {priority: 0 for priority in categories}
    children_by_parent = {}
    if nested_pairs is None:
        nested_pairs = _nested_candidate_pairs(items)
    for parent, child in nested_pairs:
        children_by_parent.setdefault(id(parent), []).append(child)

    caution_order = {"low": 0, "medium": 1, "high": 2}

    def assign(item, available_size):
        remaining = max(0, int(available_size))
        children = sorted(
            children_by_parent.get(id(item), []),
            key=lambda child: (
                caution_order.get(priority_by_id.get(id(child)), 3),
                -int(child["size"]),
                _path_key(child["path"]),
            ),
        )
        allocations = []
        for child in children:
            allocated = min(max(0, int(child["size"])), remaining)
            allocations.append((child, allocated))
            remaining -= allocated

        priority = priority_by_id.get(id(item))
        if priority in estimates:
            estimates[priority] += remaining
        for child, allocated in allocations:
            assign(child, allocated)

    for item in _non_overlapping_items(items):
        assign(item, max(0, int(item["size"])))

    return estimates


def _project_protection_lines(results, limit=8):
    """Explain which detected project roots caused candidates to be withheld."""
    skipped_count = results.get("project_candidate_count", 0)
    if not skipped_count:
        return []

    lines = [
        f"Excluded {skipped_count} possible cleanup items inside detected projects or folders Drive Cleanr could not inspect."
    ]
    roots = [
        item for item in results.get("project_roots", [])
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    ]
    roots.sort(key=lambda item: _path_key(item["path"]))
    if roots:
        lines.append("Detected project folders kept off the cleanup list:")
        for item in roots[:limit]:
            marker = item.get("marker")
            suffix = f" (project marker: {marker})" if isinstance(marker, str) and marker else ""
            lines.append(f"  {item['path']}{suffix}")
        if len(roots) > limit:
            lines.append(f"  ... and {len(roots) - limit} more project roots")
    else:
        lines.append("Some folders could not be checked for project files, so their contents were left off the cleanup list.")
    return lines


def analyze_csv(csv_path, min_size_mb=50, progress_callback=None, expand_under=None,
                expand_priority=None):
    """Analyze a scanner CSV export."""
    csv_size_bytes = os.path.getsize(csv_path)
    results = {
        "scan_file": csv_path,
        "scan_mode": _scan_mode_from_filename(csv_path),
        "scan_time": datetime.now().isoformat(),
        "scan_file_time": _scan_file_timestamp(csv_path),
        "total_size": 0,
        "free_space": 0,
        "used_space": 0,
        "space_source": None,
        "stale_candidate_count": 0,
        "project_candidate_count": 0,
        "project_roots": [],
        "temp_root_candidate_count": 0,
        "unclassified_candidate_count": 0,
        "unsafe_display_path_count": 0,
        "type_mismatch_count": 0,
        "reparse_candidate_count": 0,
        "manual_review_files": [],
        "categories": {
            "high": {"name": "High priority — lower risk (review each path)", "items": [], "total_size": 0},
            "medium": {"name": "Medium priority — review carefully", "items": [], "total_size": 0},
            "low": {"name": "Low priority — confirm the impact first", "items": [], "total_size": 0},
        }
    }

    if min_size_mb < 0:
        raise ValueError("min_size_mb must be zero or greater")
    min_size = min_size_mb * 1024 * 1024

    expand_paths = None
    if expand_under is not None:
        if isinstance(expand_under, str):
            expand_under = [expand_under]
        if not isinstance(expand_under, (list, tuple)) or not expand_under:
            raise ValueError("expand_under must contain one or more reviewed folder paths")
        if expand_priority not in (None, "high", "medium", "low"):
            raise ValueError("expand_priority must be high, medium, low, or None")
        expand_paths = []
        for expand_path in expand_under:
            if not isinstance(expand_path, str) or not _is_local_drive_path(expand_path):
                raise ValueError("Only reviewed local drive folders can be expanded")
            clean_path = expand_path.rstrip("\\/")
            if (_is_excluded_path(expand_path) or
                    scan._path_has_reparse_component(clean_path) or
                    not os.path.isdir(clean_path)):
                raise ValueError("The selected folder is protected, unavailable, or changed; scan it again")
            expand_paths.append(expand_path)
        results["expanded_candidates"] = []

    def has_named_required_headers(fields):
        keys = {str(value or "").strip().casefold().replace(" ", "") for value in fields}
        return (bool(keys & {"\u6587\u4ef6\u540d\u79f0", "filename", "name"}) and
                bool(keys & {"\u5927\u5c0f", "size", "logicalsize"}))

    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        # GUI WizTree exports may start with a generated note line. Both scanner
        # formats are accepted; WinDirStat 2.x uses Name/Logical Size/Physical Size.
        scan_mode_hint = _scan_mode_from_filename(csv_path)

        def csv_fields(line):
            return next(csv.reader([line]), [])

        def is_localized_windirstat_header(fields, sample_line):
            if len(fields) not in (9, 10):
                return False
            if not sample_line:
                return scan_mode_hint == "windirstat"
            sample = csv_fields(sample_line)
            return scan._looks_like_localized_windirstat_row(fields, sample)

        first_line_position = f.tell()
        first_line = f.readline()
        first_fields = csv_fields(first_line)
        header_is_positional_windirstat = False
        if has_named_required_headers(first_fields):
            header_position = first_line_position
        else:
            first_data_position = f.tell()
            first_data_line = f.readline()
            if is_localized_windirstat_header(first_fields, first_data_line):
                header_position = first_line_position
                header_is_positional_windirstat = True
            elif len(first_fields) in (9, 10):
                raise ValueError(
                    "CSV is missing required columns. Expected a path column (Name or File Name) "
                    "and a size column (Size or Logical Size), or a supported WinDirStat scan export."
                )
            else:
                header_position = first_data_position
                second_line = first_data_line
                second_fields = csv_fields(second_line)
                if has_named_required_headers(second_fields):
                    pass
                else:
                    second_data_line = f.readline()
                    if is_localized_windirstat_header(second_fields, second_data_line):
                        header_is_positional_windirstat = True
                    else:
                        raise ValueError(
                            "CSV is missing required columns. Expected a path column (Name or File Name) "
                            "and a size column (Size or Logical Size), or a supported WinDirStat scan export."
                        )
        f.seek(header_position)
        # Let csv.reader consume lines through readline(), not TextIOWrapper's
        # iterator protocol; the latter disables tell() for progress reporting.
        def csv_lines():
            while True:
                line = f.readline()
                if not line:
                    return
                yield line

        reader = csv.reader(csv_lines())
        headers = next(reader, [])
        header_keys = {
            str(key or '').strip().casefold().replace(' ', ''): index
            for index, key in enumerate(headers)
        }
        is_positional_windirstat = header_is_positional_windirstat
        is_windirstat_export = (
            is_positional_windirstat or 'logicalsize' in header_keys or
            'windirstatattributes' in header_keys
        )

        def column(*names):
            return next((header_keys[name] for name in names if name in header_keys), None)

        if is_positional_windirstat:
            # WinDirStat localizes column labels but keeps its documented scan
            # export order. Accept this fallback only after validating the row
            # shape, numeric size/count fields, and its internal type/index data.
            path_column, files_column, folders_column = 0, 1, 2
            size_column, physical_size_column, attributes_column = 3, 4, 5
            windirstat_attributes_column = 7
            allocated_columns = [physical_size_column]
            wiztree_allocated_columns = []
            capacity_column = free_space_column = used_space_column = None
        else:
            path_column = column('\u6587\u4ef6\u540d\u79f0', 'filename', 'name')
            size_column = column('\u5927\u5c0f', 'size', 'logicalsize')
            allocated_columns = [column(name) for name in (
                'allocated', '\u5df2\u5206\u914d', '\u5206\u914d\u5927\u5c0f', '\u5360\u7528\u7a7a\u95f4', 'physicalsize'
            )]
            allocated_columns = [name for name in allocated_columns if name is not None]
            wiztree_allocated_columns = [column(name) for name in (
                'allocated', '\u5df2\u5206\u914d', '\u5206\u914d\u5927\u5c0f', '\u5360\u7528\u7a7a\u95f4'
            )]
            wiztree_allocated_columns = [name for name in wiztree_allocated_columns if name is not None]
            attributes_column = column('attributes')
            windirstat_attributes_column = column('windirstatattributes')
            files_column = column('files')
            folders_column = column('folders')
            capacity_column = column('drivecapacity')
            free_space_column = column('freespace')
            used_space_column = column('usedspace')

        if path_column is None or size_column is None:
            raise ValueError(
                "CSV is missing required columns. Expected a path column (Name or File Name) "
                "and a size column (Size or Logical Size)."
            )

        def cell(row, index):
            return row[index] if index is not None and index < len(row) else None

        rows_processed = 0
        source_drives = set()
        project_path_cache = {}
        manual_file_reparse_cache = {}
        detected_projects = {}
        expanded_candidate_keys = set()
        manual_file_heap = []
        manual_file_sequence = 0
        for row in reader:
            rows_processed += 1
            if progress_callback and rows_processed % ANALYSIS_PROGRESS_INTERVAL == 0:
                # Report the fraction of CSV bytes consumed, not the number of
                # rows. Keep intermediate updates below 100% until parsing ends.
                bytes_processed = min(csv_size_bytes, max(0, f.tell()))
                percent_complete = min(99, bytes_processed * 100 // csv_size_bytes) \
                    if csv_size_bytes else 0
                progress_callback(percent_complete)
            try:
                # Resolve column positions once per export. csv.reader parses
                # quoted rows without allocating a dictionary for every item.
                path = cell(row, path_column) or ''
                # An on-demand folder expansion still reads the CSV from start
                # to finish for byte progress, but avoids filesystem checks for
                # rows outside the folder the user chose to inspect.
                if expand_paths and not any(_is_under(path, parent) for parent in expand_paths):
                    continue
                if not path.isprintable():
                    # Bidirectional format characters and terminal controls can
                    # make an exact cleanup target appear to name something else.
                    results["unsafe_display_path_count"] += 1
                    continue
                logical_size = int(cell(row, size_column) or 0)
                normalized_path = path.replace("/", "\\")
                drive, drive_tail = ntpath.splitdrive(normalized_path)
                if (len(drive) == 2 and drive[0].isalpha() and drive[1] == ":" and
                        drive_tail.startswith("\\") and not normalized_path.startswith("\\\\")):
                    source_drives.add(drive.upper())
                allocated_raw = next((cell(row, name) for name in allocated_columns
                                      if cell(row, name) not in (None, '')), None)
                if allocated_raw is None or allocated_raw == "":
                    size = logical_size
                else:
                    allocated_raw = str(allocated_raw).strip()
                    # WizTree prefixes hard-link allocated values with 0. Its
                    # Physical Size counterpart is a regular decimal byte count.
                    is_wiztree_allocated = any(cell(row, name) is not None
                                               for name in wiztree_allocated_columns)
                    size = (0 if is_wiztree_allocated and len(allocated_raw) > 1 and
                            allocated_raw.startswith("0") else int(allocated_raw or 0))

                # Read drive capacity when the export provides it.
                if path.rstrip("\\/").endswith(":"):
                    results["total_size"] = int(cell(row, capacity_column) or 0)
                    results["free_space"] = int(cell(row, free_space_column) or 0)
                    results["used_space"] = int(cell(row, used_space_column) or 0)
                    if results["total_size"] > 0:
                        results["space_source"] = "scan"

                # Imported CSVs are data, not authority. Only accept ordinary
                # absolute drive paths and reject roots, traversal, UNC, and
                # device paths before any item can become executable.
                if not _is_local_drive_path(path, drive, drive_tail):
                    continue

                # Skip small entries and excluded paths.
                if size <= 0 or size < min_size:
                    continue

                # Apply the safety exclusion list.
                path_components = _path_components(path, drive_tail)
                path_component_set, path_sequences = _path_match_index(path_components)
                if _is_excluded_path(path, path_components, path_component_set, path_sequences):
                    continue

                # Match the path against cleanup categories. Files outside
                # these rules can be shown separately for deliberate manual
                # review, but never become automatic cleanup suggestions.
                matched_cleanup_rule = False
                known_temp_location = _is_known_temp_location(path, path_components)
                for priority, pattern_info, pattern_components in _candidate_cleanup_rules(
                        path, path_components, path_component_set, path_sequences,
                        known_temp_location):
                    if _cleanup_rule_matches(pattern_info, pattern_components, path_components,
                                             path_component_set, path_sequences, path=path,
                                             known_temp_location=known_temp_location):
                        matched_cleanup_rule = True
                        # Folder browsing honors the review level the user
                        # selected. Do not let a more cautious match fall
                        # through to a broader, lower-risk label.
                        if expand_paths and expand_priority is not None and priority != expand_priority:
                            break
                        # Type metadata is only needed for candidates; most
                        # scanner rows are ordinary files we can skip here.
                        if scan._path_has_reparse_component(path.rstrip("\\/")):
                            results["reparse_candidate_count"] += 1
                        elif not os.path.exists(path.rstrip("\\/")):
                            results["stale_candidate_count"] += 1
                        else:
                            scanner_type = 'directory' if path.endswith(('\\', '/')) else None
                            if scanner_type is None and is_windirstat_export:
                                scanner_type = _is_directory_row({
                                    'attributes': cell(row, attributes_column),
                                    'windirstatattributes': cell(row, windirstat_attributes_column),
                                    'files': cell(row, files_column),
                                    'folders': cell(row, folders_column),
                                })
                            elif scanner_type is None:
                                # WizTree represents directory rows with a trailing separator.
                                scanner_type = 'file'

                            current_path = path.rstrip('\\/')
                            if os.path.isdir(current_path):
                                current_type = 'directory'
                            elif os.path.isfile(current_path):
                                current_type = 'file'
                            else:
                                current_type = None

                            if current_type is None:
                                results['unclassified_candidate_count'] += 1
                            elif scanner_type is not None and scanner_type != current_type:
                                # Old exports can have stale type metadata (for
                                # example, a former folder path now naming a file).
                                # Do not build a destructive plan from that row.
                                results['type_mismatch_count'] += 1
                            else:
                                # Use the current filesystem as the authority when
                                # WinDirStat did not provide reliable type metadata.
                                row_is_directory = current_type == 'directory'
                                if row_is_directory and not path.endswith(('\\', '/')):
                                    path += '\\'
                                if _inside_project_tree(
                                    path, row_is_directory, project_path_cache,
                                    detected_projects=detected_projects,
                                ):
                                    results["project_candidate_count"] += 1
                                elif (row_is_directory and pattern_info.get("known_temp_location") and
                                      _is_known_temp_root(path, path_components)):
                                    # Offer qualifying contents inside a known
                                    # temp root individually, so selecting the
                                    # root cannot sweep up unrelated installers
                                    # or work in progress as one broad target.
                                    results["temp_root_candidate_count"] += 1
                                else:
                                    candidate_item = {
                                        "path": path,
                                        "size": size,
                                        "size_formatted": format_size(size),
                                        "name": pattern_info["name"],
                                        "safe": pattern_info["safe"],
                                        "kind": classify_path(path),
                                    }
                                    if (expand_paths and
                                            (expand_priority is None or priority == expand_priority) and
                                            any(_is_under(path, parent) for parent in expand_paths)):
                                        candidate_key = (priority, _path_key(path))
                                        if candidate_key not in expanded_candidate_keys:
                                            results["expanded_candidates"].append({
                                                "priority": priority,
                                                "item": candidate_item,
                                            })
                                            expanded_candidate_keys.add(candidate_key)

                                    # Avoid double-counting an entry under a selected parent.
                                    existing_paths = [item["path"] for item in results["categories"][priority]["items"]]
                                    is_subdir = any(_is_under(path, p) for p in existing_paths)

                                    if not is_subdir:
                                        # Replace selected children with this outer directory.
                                        results["categories"][priority]["items"] = [
                                            item for item in results["categories"][priority]["items"]
                                            if not _is_under(item["path"], path) and _path_key(item["path"]) != _path_key(path)
                                        ]

                                        results["categories"][priority]["items"].append(candidate_item)
                        break
                if not matched_cleanup_rule and not expand_paths:
                    scanner_type = 'directory' if path.endswith(('\\', '/')) else None
                    if scanner_type is None and is_windirstat_export:
                        scanner_type = _is_directory_row({
                            'attributes': cell(row, attributes_column),
                            'windirstatattributes': cell(row, windirstat_attributes_column),
                            'files': cell(row, files_column),
                            'folders': cell(row, folders_column),
                        })
                    elif scanner_type is None:
                        scanner_type = 'file'
                    if scanner_type == 'file':
                        # Rank only files that can actually appear in the
                        # manual-review list. Filtering projects and redirected
                        # paths after building a bounded shortlist can let
                        # hundreds of ineligible large files hide eligible
                        # files lower in the scan's size ranking.
                        can_enter_shortlist = (
                            len(manual_file_heap) < MANUAL_REVIEW_HEAP_LIMIT or
                            size > manual_file_heap[0][0]
                        )
                        if can_enter_shortlist:
                            current_path = path.rstrip('\\/')
                            if (not _path_has_reparse_component_cached(
                                    current_path, manual_file_reparse_cache) and
                                    os.path.isfile(current_path) and
                                    not os.path.isdir(current_path) and
                                    not _inside_project_tree(
                                        path, False, project_path_cache,
                                        detected_projects=detected_projects)):
                                manual_file_sequence += 1
                                manual_file = (size, manual_file_sequence, path)
                                if len(manual_file_heap) < MANUAL_REVIEW_HEAP_LIMIT:
                                    heapq.heappush(manual_file_heap, manual_file)
                                else:
                                    heapq.heapreplace(manual_file_heap, manual_file)
            except (ValueError, KeyError):
                continue

    # WinDirStat exports do not include volume capacity. If this is a local
    # single-drive export, offer current space values with an explicit label.
    if results["space_source"] is None and len(source_drives) == 1:
        try:
            usage = shutil.disk_usage(next(iter(source_drives)) + "\\")
            results["total_size"] = usage.total
            results["used_space"] = usage.used
            results["free_space"] = usage.free
            results["space_source"] = "current"
        except OSError:
            pass

    # Recheck shortlisted files at the end in case their type, protection,
    # project markers, or reparse-point status changed while the CSV was read.
    manual_files_seen = set()
    final_manual_project_cache = {}
    final_manual_reparse_cache = {}
    for size, _sequence, path in sorted(
            manual_file_heap, key=lambda entry: (-entry[0], entry[2].casefold())):
        path_key = _path_key(path)
        if path_key in manual_files_seen:
            continue
        manual_files_seen.add(path_key)
        current_path = path.rstrip('\\/')
        if (_path_has_reparse_component_cached(current_path, final_manual_reparse_cache) or
                _is_excluded_path(path) or _matches_any_cleanup_rule(path) or
                not os.path.isfile(current_path) or os.path.isdir(current_path)):
            continue
        if _inside_project_tree(
                path, False, final_manual_project_cache,
                detected_projects=detected_projects):
            continue
        results["manual_review_files"].append({
            "path": path,
            "size": size,
            "size_formatted": format_size(size),
            "name": MANUAL_REVIEW_LABEL,
            "kind": "File",
            "manual_review": True,
        })
        if len(results["manual_review_files"]) >= MANUAL_REVIEW_FILE_LIMIT:
            break

    # Calculate category totals and sort candidates by size.
    for priority in results["categories"]:
        items = results["categories"][priority]["items"]
        items.sort(key=lambda x: x["size"], reverse=True)
        results["categories"][priority]["total_size"] = sum(item["size"] for item in items)
        results["categories"][priority]["total_size_formatted"] = format_size(
            results["categories"][priority]["total_size"]
        )

    results["project_roots"] = sorted(
        detected_projects.values(), key=lambda item: _path_key(item["path"])
    )
    if progress_callback:
        progress_callback(100)

    return results


def print_category_items(category, show_all=False, item_limit=10):
    """Print candidate items for a cleanup category."""
    items = category["items"]
    if not items:
        return

    visible_items = items if show_all else items[:item_limit]
    for item in visible_items:
        print(f"  {item['size_formatted']:>10}  {display_item_type(item)}  {item['name']}")
        print(f"             {item['path']}")

    if not show_all and len(items) > item_limit:
        print(f"  ... and {len(items) - item_limit} more items")


def display_item_type(item):
    """Use familiar file/folder labels in user-facing reports and pickers."""
    kind = item.get("kind", "")
    if not isinstance(kind, str):
        return "Type unavailable"
    normalized = kind.casefold()
    # Localized scanner metadata is accepted as input but never shown to users.
    if normalized in {"directory", "folder", "\u76ee\u5f55"}:
        return "Folder"
    if normalized == "file":
        return "File"
    return "Type unavailable"


def print_report(results, show_all_items=False, item_limit=10):
    """Print the analysis report."""
    print("=" * 60)
    print("                 Drive Cleanr Scan Review")
    print("=" * 60)
    print()
    scan_file_time = _safe_scan_timestamp(results)
    print(f"Scan file last changed: {scan_file_time}")
    print("Files and folders may have changed since this scan. Scan again before cleanup if anything may have changed.")

    if results.get("scan_mode") == "wiztree_standard":
        print("Scan mode: WizTree standard file-system scan; files inaccessible to this account may be missing.")
    elif results.get("scan_mode") == "wiztree_fast":
        print("Scan mode: WizTree fast full-drive scan.")
    elif results.get("scan_mode") == "windirstat":
        print("Scan mode: WinDirStat; saved filters and access permissions apply.")

    if results["total_size"] > 0:
        if results.get("space_source") == "current":
            print(f"Current capacity: {format_size(results['total_size'])}")
            print(f"Current used:     {format_size(results['used_space'])}")
            print(f"Current free:     {format_size(results['free_space'])}")
            print("Volume space was checked now; this may differ from the time of the scan.")
        else:
            print(f"Total capacity: {format_size(results['total_size'])}")
            print(f"Used space:     {format_size(results['used_space'])}")
            print(f"Free space:     {format_size(results['free_space'])}")
        print()

    all_items = [item for category in results["categories"].values() for item in category["items"]]
    nested_pairs = _nested_candidate_pairs(all_items)
    for line in _nested_candidate_summary(all_items, nested_pairs):
        print(line)
    if nested_pairs:
        print(
            "The same space is counted once in the total, even when items appear in different review groups. Each folder row still shows its full size."
        )
    tier_estimates = _tier_size_estimates(results["categories"], nested_pairs)

    for priority in ["high", "medium", "low"]:
        category = results["categories"][priority]
        if category["items"]:
            print("-" * 60)
            print(f"[{category['name']}] - Estimated space: {format_size(tier_estimates[priority])}")
            print("-" * 60)

            print_category_items(category, show_all=show_all_items, item_limit=item_limit)

            print()

    manual_files = results.get("manual_review_files", [])
    if isinstance(manual_files, list) and manual_files:
        print("-" * 60)
        print("[Largest files outside automatic cleanup suggestions — manual review only]")
        print("These files are not cleanup recommendations. Drive Cleanr cannot tell whether you need them.")
        print("They are excluded from the suggested-space total and any plan unless you select each exact file.")
        print("-" * 60)
        print_category_items(
            {"items": manual_files}, show_all=show_all_items, item_limit=item_limit
        )
        if not show_all_items and len(manual_files) > item_limit:
            print(f"  ... and {len(manual_files) - item_limit} more manual-review files (up to {MANUAL_REVIEW_FILE_LIMIT} shown in the picker)")
        print()

    print("=" * 60)
    unique_size = sum(item["size"] for item in _non_overlapping_items(all_items))
    print(f"Estimated space in automatic cleanup suggestions (counted once): {format_size(unique_size)}")
    print("Drive Cleanr protects Windows system data, recovery data, personal folders, messaging data, and credentials.")
    print("WizTree allocated sizes are used when available; hard-linked files are excluded. Actual free space may differ.")
    print("Folder sizes can include protected contents that cleanup keeps, so the space recovered may be lower.")
    print("Lower-risk items are usually recreatable, but review every path before cleanup.")
    if results.get("stale_candidate_count", 0):
        print(f"Skipped {results['stale_candidate_count']} listed files or folders that no longer exist.")
    if results.get("unsafe_display_path_count", 0):
        print(
            f"Skipped {results['unsafe_display_path_count']} scan entries with hidden or control characters in their paths; they cannot be shown safely for review."
        )
    for line in _project_protection_lines(results):
        print(line)
    if results.get("temp_root_candidate_count", 0):
        print(f"Known temporary folders skipped: {results['temp_root_candidate_count']}; files and folders inside are shown separately when they match the cleanup rules.")
    if results.get("unclassified_candidate_count", 0):
        print(f"Skipped {results['unclassified_candidate_count']} entries whose file or folder type could not be confirmed; rescan to see complete details.")
    if results.get("type_mismatch_count", 0):
        print(f"Skipped {results['type_mismatch_count']} entries whose file or folder type changed since the scan; rescan to refresh the results.")
    if results.get("reparse_candidate_count", 0):
        print(f"Skipped {results['reparse_candidate_count']} paths that pass through a link or could not be checked.")
    print("=" * 60)


def generate_clean_script(results, output_path, priority="high", selected_paths=None,
                          manual_review_confirmed=False):
    """Generate a reviewed PowerShell cleanup script."""
    if priority not in {"high", "medium", "low", "all", "manual"}:
        raise ValueError("priority must be high, medium, low, all, or manual")
    categories = results.get("categories")
    if not isinstance(categories, dict):
        raise ValueError("Cleanup plan contains malformed candidate categories")
    priority_order = ("high", "medium", "low")
    if priority == "manual":
        if selected_paths is None or not manual_review_confirmed:
            raise ValueError("Manual-review files require an explicit reviewed selection")
        manual_items = results.get("manual_review_files")
        if not isinstance(manual_items, list):
            raise ValueError("Manual-review files are missing or malformed")
        source_items = [("manual", item) for item in manual_items]
        priority_name = "Manual review - exact files selected by the user"
    elif priority == "all":
        source_items = []
        for key in priority_order:
            category = categories.get(key)
            if not isinstance(category, dict) or not isinstance(category.get("items"), list):
                raise ValueError("Cleanup plan contains malformed candidate categories")
            source_items.extend((key, item) for item in category["items"])
        priority_name = "All priorities (high / medium / low)"
    else:
        category = categories.get(priority)
        if not isinstance(category, dict) or not isinstance(category.get("items"), list):
            raise ValueError("Cleanup plan contains malformed candidate categories")
        source_items = [(priority, item) for item in category["items"]]
        priority_name = CLEANABLE_PATTERNS[priority]["name"]

    selected_keys = set()
    if selected_paths is not None:
        if not isinstance(selected_paths, (list, tuple)):
            raise ValueError("Selected cleanup paths must be a list of reviewed candidates")
        for path in selected_paths:
            if not isinstance(path, str) or not path:
                raise ValueError("Selected cleanup paths contain an invalid path")
            selected_keys.add(_path_key(path))
        if not selected_keys:
            raise ValueError("Select at least one cleanup candidate before creating a plan")

        available_keys = {
            _path_key(item["path"])
            for _candidate_priority, item in source_items
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        }
        unknown_keys = selected_keys - available_keys
        if unknown_keys:
            raise ValueError("A selected cleanup path is not in the chosen candidate list")
        source_items = [
            (candidate_priority, item)
            for candidate_priority, item in source_items
            if isinstance(item, dict) and isinstance(item.get("path"), str)
            and _path_key(item["path"]) in selected_keys
        ]

    items = [item for _candidate_priority, item in source_items]

    # Candidate data can come from imported or edited results, so reapply the
    # path and project protections at the plan-generation boundary as well.
    project_path_cache = {}

    def validate_candidate(item, candidate_priority):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("Cleanup plan contains a malformed target")
        path = item["path"]
        if (not isinstance(item.get("name"), str) or
                not isinstance(item.get("size_formatted"), str) or
                not isinstance(item.get("size"), int) or item["size"] < 0):
            raise ValueError("Cleanup plan contains a malformed target")
        if not _is_local_drive_path(path):
            raise ValueError("Cleanup plan contains an unsafe path; only absolute non-root local paths are allowed")
        if scan._path_has_reparse_component(path.rstrip("\\/")):
            raise ValueError("Cleanup plan contains a path that crosses a junction or symbolic link; rescan before cleanup")
        if _is_excluded_path(path):
            raise ValueError("Cleanup plan contains a protected path; remove it and rescan")
        kind = item.get("kind", classify_path(path))
        if not isinstance(kind, str) or kind.lower() not in ("file", "directory", "folder", "\u76ee\u5f55"):
            raise ValueError("Cleanup plan contains an invalid target type")
        is_directory = kind.lower() in ("directory", "folder", "\u76ee\u5f55")
        if candidate_priority == "manual":
            if (item.get("manual_review") is not True or is_directory or
                    item["name"] != MANUAL_REVIEW_LABEL or
                    not os.path.isfile(path.rstrip("\\/")) or
                    os.path.isdir(path.rstrip("\\/")) or _matches_any_cleanup_rule(path)):
                raise ValueError("Manual-review plans accept only current, unprotected files not matched by cleanup rules")
        elif not _matches_cleanup_rule(path, (candidate_priority,), item["name"]):
            raise ValueError("Cleanup plan target does not match its priority and cleanup label; rescan before cleanup")
        if _inside_project_tree(path, is_directory, project_path_cache):
            raise ValueError("Cleanup plan contains a path inside a detected project folder")
        return is_directory

    source_types = {}
    for candidate_priority, item in source_items:
        source_types[id(item)] = validate_candidate(item, candidate_priority)

    # A selected folder may contain a candidate from a more cautious tier.
    # Keep that nested path out of this plan's recursive cleanup, even when
    # the user selected the parent folder or requested all priorities.
    preserved_candidates = {}
    selected_nested_candidates = {}
    for outer_priority, outer_item in source_items:
        if not source_types[id(outer_item)]:
            continue
        outer_path = outer_item["path"]
        outer_key = _path_key(outer_path)
        nested_paths = preserved_candidates.setdefault(outer_key, [])
        selected_nested_paths = selected_nested_candidates.setdefault(outer_key, [])
        selected_nested_keys = {_path_key(path) for path in selected_nested_paths}
        for _nested_priority, selected_item in source_items:
            if selected_item is outer_item:
                continue
            selected_path = selected_item["path"]
            if not _is_under(selected_path, outer_path):
                continue
            selected_key = _path_key(selected_path)
            if selected_key not in selected_nested_keys:
                selected_nested_paths.append(ntpath.normpath(selected_path.replace("/", "\\")))
                selected_nested_keys.add(selected_key)
        for nested_priority in priority_order:
            if _CLEANUP_TIE_BREAK_RANK[nested_priority] >= _CLEANUP_TIE_BREAK_RANK[outer_priority]:
                continue
            nested_category = categories.get(nested_priority)
            if nested_category is None:
                continue
            if not isinstance(nested_category, dict) or not isinstance(nested_category.get("items"), list):
                raise ValueError("Cleanup plan contains malformed candidate categories")
            for nested_item in nested_category["items"]:
                if not isinstance(nested_item, dict) or not isinstance(nested_item.get("path"), str):
                    raise ValueError("Cleanup plan contains a malformed nested candidate")
                nested_path = nested_item["path"]
                if not _is_under(nested_path, outer_path):
                    continue
                # An explicit nested selection overrides the parent folder's
                # default protection for that candidate. The emitted plan
                # still uses the parent as its single cleanup/backup target.
                if _path_key(nested_path) in selected_keys:
                    continue
                validate_candidate(nested_item, nested_priority)
                nested_path = ntpath.normpath(nested_path.replace("/", "\\"))
                if not any(
                        _path_key(nested_path) == _path_key(existing) or
                        _is_under(nested_path, existing)
                        for existing in nested_paths):
                    nested_paths.append(nested_path)

    if priority == "all":
        # Validate each source-tier entry before deduplicating so malformed
        # imported results cannot bypass the plan-generation checks.
        deduped = {}
        for item in items:
            deduped[_path_key(item["path"])] = item
        items = list(deduped.values())

    # A parent candidate covers descendants even when rules put them in
    # different tiers. Emit a non-overlapping plan to prevent double counting.
    items = _non_overlapping_items(items)
    if not items:
        raise ValueError("No cleanup candidates were found for the selected priority")
    _ensure_output_outside_targets(output_path, items)
    default_selection = (
        ", ".join(str(index) for index in range(1, len(items) + 1))
        if selected_paths is not None else ""
    )

    native_class_name = "DriveCleanrCleanupGuard_" + hashlib.sha256(
        _CLEANUP_NATIVE_GUARD_SOURCE.encode("utf-8")
    ).hexdigest()[:12]
    native_source = _CLEANUP_NATIVE_GUARD_SOURCE.replace("__CLASS_NAME__", native_class_name)
    native_guard = (
        f'if (-not ("{native_class_name}" -as [type])) {{\n'
        "Add-Type -TypeDefinition @'\n"
        + native_source
        + "\n'@ -ErrorAction Stop\n}\n"
    )
    backup_script_literal = _ps_literal(
        str(Path(__file__).resolve().with_name("backup.py"))
    )

    script = '''# Drive Cleanr Cleanup Plan - {priority_name}
# Auto-generated: {timestamp}
# Source scan last modified: {scan_file_time}
# Run in PowerShell with only the permissions needed for the selected paths.

param(
    [switch]$Force,
    [Alias("Backup")][switch]$CreateBackup,
    [Alias("NoBackup")][switch]$SkipBackup,
    [switch]$PreviewOnly,
    [int[]]$Select = @({default_selection})
)

$ErrorActionPreference = "Stop"
$ManualReviewOnly = {manual_review_only}
if ($CreateBackup -and $SkipBackup) {{
    throw "Choose either -Backup or -NoBackup, not both."
}}

function Format-PreviewFileDataSize([decimal]$Bytes) {{
    $exactBytes = $Bytes.ToString("0", [System.Globalization.CultureInfo]::InvariantCulture)
    if ($Bytes -lt 1024) {{ return "$exactBytes bytes" }}
    $units = @("KB", "MB", "GB", "TB", "PB", "EB")
    $value = [double]$Bytes
    $unitIndex = -1
    do {{
        $value /= 1024
        $unitIndex++
    }} while ($value -ge 1024 -and $unitIndex -lt ($units.Count - 1))
    $formattedValue = $value.ToString("0.00", [System.Globalization.CultureInfo]::InvariantCulture)
    return "$formattedValue $($units[$unitIndex]) ($exactBytes bytes)"
}}

function Write-PreviewFolderSizeProgress([long]$Current, [long]$Total) {{
    if ($Total -le 0 -or
        ($Current -ne 1 -and ($Current % 1000) -ne 0 -and $Current -ne $Total)) {{
        return
    }}
    $status = "$Current of $Total folder-size entries checked."
    $percentComplete = [int](100.0 * $Current / $Total)
    Write-Progress -Activity "Summarizing eligible folder sizes" -Status $status -PercentComplete $percentComplete
    Write-Host "  Folder size summary: $status" -ForegroundColor Gray
}}

__NATIVE_CLEANUP_GUARD__

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "       Drive Cleanr Cleanup Plan - {priority_name}" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {{
    Write-Host "[Warning] This window is not running as Administrator; Windows may block access to some files." -ForegroundColor Yellow
}}

# Check related processes
$chrome = Get-Process -Name "chrome" -ErrorAction SilentlyContinue
$edge = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
if ($chrome -or $edge) {{
    Write-Host "[Warning] A browser is running; some cache items may not be fully cleanable" -ForegroundColor Yellow
}}
$vscode = Get-Process -Name "Code" -ErrorAction SilentlyContinue
if ($vscode) {{
    Write-Host "[Warning] VS Code is running; its cache cleanup may be incomplete" -ForegroundColor Yellow
}}
$javaproc = Get-Process -Name "java" -ErrorAction SilentlyContinue
if ($javaproc) {{
    Write-Host "[Warning] Java is running (possibly a Gradle daemon); build cache cleanup may be incomplete" -ForegroundColor Yellow
}}
$condaproc = Get-Process -Name "conda", "mamba", "micromamba", "pixi" -ErrorAction SilentlyContinue
if ($condaproc) {{
    Write-Host "[Warning] A Conda, Mamba, or Pixi operation is running; defer package-cache cleanup until it finishes" -ForegroundColor Yellow
}}
$nodeproc = Get-Process -Name "node", "npm", "yarn", "pnpm" -ErrorAction SilentlyContinue
if ($nodeproc) {{
    Write-Host "[Warning] A Node.js or package-manager process is running; defer related cache cleanup until it finishes" -ForegroundColor Yellow
}}
$rustproc = Get-Process -Name "cargo", "rustc" -ErrorAction SilentlyContinue
if ($rustproc) {{
    Write-Host "[Warning] A Rust/Cargo process is running; defer related cache or temporary-folder cleanup until it finishes" -ForegroundColor Yellow
}}
$goproc = Get-Process -Name "go" -ErrorAction SilentlyContinue
if ($goproc) {{
    Write-Host "[Warning] A Go process is running; defer Go module cache cleanup until it finishes" -ForegroundColor Yellow
}}
$dotnetproc = Get-Process -Name "dotnet", "MSBuild" -ErrorAction SilentlyContinue
if ($dotnetproc) {{
    Write-Host "[Warning] A .NET build process is running; defer NuGet package cleanup until it finishes" -ForegroundColor Yellow
}}
$installproc = Get-Process -Name "msiexec", "TiWorker", "TrustedInstaller", "MoUsoCoreWorker", "SetupHost", "winget", "choco", "scoop" -ErrorAction SilentlyContinue
if ($installproc) {{
    Write-Host "[Warning] A Windows installer, updater, or package manager is running; defer related temporary-folder cleanup until it finishes" -ForegroundColor Yellow
}}

$cleanTargets = @(
{targets}
)
$protectedPathPattern = [regex]::new({protected_pattern}, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
$projectMarkers = @(
{project_markers}
)
$projectMarkerSuffixPattern = [regex]::new({project_marker_suffix_pattern}, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
$profileRootIgnoredMarkers = @('.editorconfig', '.vscode', '.cursorrules', '.claude', '.cursor', '.gemini', '.github', '.opencode', '.windsurf', 'agents.md', 'agents.override.md', 'claude.md', 'gemini.md', 'copilot-instructions.md', 'skill.md', 'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'bun.lock', 'bun.lockb', 'pnpm-lock.yaml', 'yarn.lock')

function Test-DirectoryHasProjectMarker([string]$Directory, [bool]$ShowProgress = $false) {{
    try {{
        $directoryItem = Get-Item -LiteralPath $Directory -Force -EA Stop
        if (-not $directoryItem.PSIsContainer -or
            ($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{
            return $true
        }}
        $normalizedDirectory = $Directory.TrimEnd('\\')
        $isProfileRoot = $normalizedDirectory -match '^[A-Za-z]:\\\\(?:Users|Documents and Settings)\\\\[^\\\\]+$'
        $entryCount = 0
        $hasProjectMarker = $false
        $projectCheckWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $lastProjectNoticeSeconds = 0
        foreach ($entryPath in [System.IO.Directory]::EnumerateFileSystemEntries($Directory)) {{
            $entryCount++
            $entryName = [System.IO.Path]::GetFileName($entryPath)
            $elapsedProjectSeconds = [int]$projectCheckWatch.Elapsed.TotalSeconds
            if ($ShowProgress -and ($entryCount -eq 1 -or ($entryCount % 100) -eq 0 -or
                ($elapsedProjectSeconds - $lastProjectNoticeSeconds) -ge 10)) {{
                $projectCheckStatus = if ($entryCount -eq 1) {{
                    "First entry checked for project files."
                }} else {{
                    "$entryCount entries checked for project files."
                }}
                Write-Progress -Activity "Checking selected paths for project files" -Status $projectCheckStatus
                Write-Host "  Project check: $projectCheckStatus" -ForegroundColor Gray
                $lastProjectNoticeSeconds = $elapsedProjectSeconds
            }}
            if ($isProfileRoot -and ($profileRootIgnoredMarkers -contains $entryName -or $entryName -like '*.code-workspace')) {{ continue }}
            if ($projectMarkers -contains $entryName) {{ $hasProjectMarker = $true; break }}
            if ($projectMarkerSuffixPattern.IsMatch($entryName) -and
                -not [System.IO.Directory]::Exists($entryPath)) {{ $hasProjectMarker = $true; break }}
        }}
        if ($ShowProgress) {{
            Write-Progress -Activity "Checking selected paths for project files" -Completed
            $projectCheckSummary = if ($hasProjectMarker) {{
                "Project marker found after checking $entryCount entries in this folder."
            }} else {{
                "Project marker check complete; $entryCount entries checked in this folder."
            }}
            Write-Host "  $projectCheckSummary" -ForegroundColor Gray
        }}
        return $hasProjectMarker
    }} catch {{
        # A directory that cannot be checked must not be treated as disposable.
        if ($ShowProgress) {{ Write-Progress -Activity "Checking selected paths for project files" -Completed }}
        return $true
    }}
}}

function Test-PathInsideProject([string]$Path, [bool]$IsDirectory, [bool]$ShowProgress = $false) {{
    if ($ShowProgress) {{
        Write-Host "Checking this item and its parent folders for project files. This can take a while." -ForegroundColor Gray
    }}
    $current = if ($IsDirectory) {{ $Path }} else {{ [System.IO.Path]::GetDirectoryName($Path) }}
    while ($current) {{
        if (Test-DirectoryHasProjectMarker $current $ShowProgress) {{ return $true }}
        $normalizedCurrent = $current.TrimEnd('\\')
        if ($normalizedCurrent -match '^[A-Za-z]:\\\\(?:Users|Documents and Settings)(?:\\\\[^\\\\]+)?$') {{ break }}
        $parent = [System.IO.Directory]::GetParent($current)
        if (-not $parent) {{ break }}
        $current = $parent.FullName
    }}
    return $false
}}

function Assert-TargetMatchesScan([object]$Target) {{
    $current = [System.IO.Path]::GetFullPath($Target.Path)
    $isTarget = $true
    while ($current) {{
        $item = Get-Item -LiteralPath $current -Force -EA Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{
            throw "The target or one of its parent paths is now a reparse point; refusing cleanup: $($Target.Path)"
        }}
        if ($isTarget -and [bool]$item.PSIsContainer -ne [bool]$Target.IsDirectory) {{
            throw "The item type changed since the scan; rescan before cleanup: $($Target.Path)"
        }}
        $parent = [System.IO.Directory]::GetParent($current)
        if (-not $parent) {{ break }}
        $current = $parent.FullName
        $isTarget = $false
    }}
}}

function Get-CleanupProtectedRoot([string]$FullName, [string]$Name, [bool]$IsDirectory) {{
    $protectedRoot = $null
    if ($Name -like 'claude*') {{ $protectedRoot = $FullName }}
    if ($projectMarkers -contains $Name) {{
        $protectedRoot = [System.IO.Directory]::GetParent($FullName).FullName
    }}
    if (-not $IsDirectory -and $projectMarkerSuffixPattern.IsMatch($Name)) {{
        $protectedRoot = [System.IO.Directory]::GetParent($FullName).FullName
    }}
    $normalizedPath = $FullName.TrimEnd('\\') + '\\'
    if ($protectedPathPattern.IsMatch($normalizedPath) -and -not $protectedRoot) {{
        $protectedRoot = $FullName
    }}
    return $protectedRoot
}}

function New-CleanupHashProgressAction([long]$FileIndex, [long]$FileTotal, [string]$ItemLabel = "file") {{
    $progressWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $progressScript = {{
        param([long]$BytesProcessed, [long]$FileBytesTotal)
        if ($FileBytesTotal -le 0 -or $FileTotal -le 0) {{ return }}
        if ($FileBytesTotal -lt 1MB -and $BytesProcessed -eq $FileBytesTotal -and
            $progressWatch.Elapsed.TotalSeconds -lt 10) {{ return }}
        $filePercent = [int][Math]::Min(100, (100.0 * $BytesProcessed / $FileBytesTotal))
        $overallPercent = [int](100.0 * (($FileIndex - 1) + ($BytesProcessed / $FileBytesTotal)) / $FileTotal)
        $processedMB = [math]::Round($BytesProcessed / 1MB, 1)
        $totalMB = [math]::Round($FileBytesTotal / 1MB, 1)
        $itemTitle = $ItemLabel.Substring(0, 1).ToUpperInvariant() + $ItemLabel.Substring(1)
        $progressStatus = "Checking $ItemLabel $FileIndex of $FileTotal; $filePercent% checked ($processedMB of $totalMB MB). This check does not remove files."
        Write-Progress -Activity "Checking selected $ItemLabel contents" -Status $progressStatus -PercentComplete $overallPercent
        Write-Host ("  {{0}} {{1}} of {{2}}: {{3:N1}} MB of {{4:N1}} MB checked ({{5}}%)." -f $itemTitle, $FileIndex, $FileTotal, $processedMB, $totalMB, $filePercent) -ForegroundColor Gray
    }}.GetNewClosure()
    return [System.Action[long, long]]$progressScript
}}

function Assert-CleanupEntryPathWithinSelection([object]$Target, [object]$Entry) {{
    # Keep only the lexical containment check here. The native removal routine
    # validates type, reparse-point status, identity, size, and last-write time
    # on its locked handle immediately before deletion.
    $targetRoot = [System.IO.Path]::GetFullPath($Target.Path)
    $targetRootWithSeparator = $targetRoot.TrimEnd([char[]]@(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )) + [System.IO.Path]::DirectorySeparatorChar
    $entryPath = [System.IO.Path]::GetFullPath($Entry.FullName)
    if (-not $entryPath.StartsWith($targetRootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {{
        throw "A cleanup entry moved outside its selected folder; refusing cleanup: $entryPath"
    }}
}}

$available = @()
if ($ManualReviewOnly) {{
    Write-Host "Manual review only: these files did not match Drive Cleanr's cleanup rules." -ForegroundColor Yellow
    Write-Host "Drive Cleanr cannot tell whether they are needed. Check every exact path before continuing." -ForegroundColor Yellow
}}
if ($Select.Count -gt 0) {{
    if ($ManualReviewOnly) {{
        Write-Host "Individual files already selected for this manual-review plan:" -ForegroundColor White
    }} else {{
        Write-Host "Files and folders already selected for this plan:" -ForegroundColor White
    }}
}} else {{
    if ($ManualReviewOnly) {{
        Write-Host "Individual files available for manual review:" -ForegroundColor White
    }} else {{
        Write-Host "Files and folders available to choose from:" -ForegroundColor White
    }}
}}
for ($i = 0; $i -lt $cleanTargets.Count; $i++) {{
    $target = $cleanTargets[$i]
    $target | Add-Member -NotePropertyName Index -NotePropertyValue ($i + 1) -Force | Out-Null
    if (Test-Path -LiteralPath $target.Path) {{
        $available += $target
        Write-Host "  [$($target.Index)] $($target.ItemType) | $($target.Name) | $($target.Size) | $($target.Path)" -ForegroundColor White
    }} else {{
        Write-Host "  [Missing] $($target.ItemType) | $($target.Name) | $($target.Path)" -ForegroundColor Gray
    }}
}}
if ($available.Count -eq 0) {{
    if ($PreviewOnly) {{
        Write-Host "Preview incomplete: none of the selected files or folders still exist. Nothing was changed." -ForegroundColor Yellow
        exit 1
    }}
    Write-Host "None of the files or folders in this plan still exist." -ForegroundColor Yellow
    exit 0
}}
$availableIndexes = @($available | ForEach-Object {{ $_.Index }})

if ($Select.Count -gt 0) {{
    $invalid = @($Select | Where-Object {{ $availableIndexes -notcontains $_ }})
    if ($invalid.Count -gt 0) {{ throw "Selection index is unavailable. Existing item numbers: $($availableIndexes -join ', ')." }}
    $cleanTargets = @()
    foreach ($index in ($Select | Select-Object -Unique)) {{
        $cleanTargets += @($available | Where-Object {{ $_.Index -eq $index }})
    }}
}} else {{
    $choicePrompt = if ($ManualReviewOnly) {{
        "Choose listed files by number (comma-separated), A for all, or Q to cancel"
    }} else {{
        "Choose listed files or folders by number (comma-separated), A for all, or Q to cancel"
    }}
    $choice = Read-Host $choicePrompt
    if ([string]::IsNullOrWhiteSpace($choice) -or $choice -match '^(?i:q|quit)$') {{
        Write-Host "Cancelled; nothing was changed." -ForegroundColor Yellow
        exit 0
    }} elseif ($choice -match '^(?i:a|all)$') {{
        $cleanTargets = $available
    }} else {{
        $numbers = @()
        foreach ($token in ($choice -split '[,; ]+')) {{
            $number = 0
            if (-not [int]::TryParse($token, [ref]$number)) {{ throw "Invalid selection '$token'. Enter item numbers, A, or Q." }}
            $numbers += $number
        }}
        $invalid = @($numbers | Where-Object {{ $availableIndexes -notcontains $_ }})
        if ($invalid.Count -gt 0) {{ throw "Selection index is unavailable. Existing item numbers: $($availableIndexes -join ', ')." }}
        $cleanTargets = @()
        foreach ($index in ($numbers | Select-Object -Unique)) {{
            $cleanTargets += @($available | Where-Object {{ $_.Index -eq $index }})
        }}
    }}
}}

$targetSnapshotIndex = 0
foreach ($target in $cleanTargets) {{
    $targetSnapshotIndex++
    Assert-TargetMatchesScan $target
    if (Test-PathInsideProject $target.Path ([bool]$target.IsDirectory) $true) {{
        throw "A selected target is now inside a project or an unreadable folder; rescan before cleanup: $($target.Path)"
    }}
    if ([bool]$target.IsDirectory) {{
        Write-Host "Checking selected folder $targetSnapshotIndex of $($cleanTargets.Count) for folder identity and extra Windows file data; this check does not remove files." -ForegroundColor Gray
        $directoryProgressAction = New-CleanupHashProgressAction $targetSnapshotIndex $cleanTargets.Count "folder"
        $directorySnapshot = [{native_class_name}]::GetDirectoryIdentityAndStreamsHash($target.Path, $directoryProgressAction)
        $directorySnapshotParts = $directorySnapshot -split '\\|', 2
        if ($directorySnapshotParts.Count -ne 2) {{ throw "Could not verify the selected folder's identity and named data streams." }}
        $cleanupIdentity = $directorySnapshotParts[0]
        $target | Add-Member -NotePropertyName CleanupStreamsSha256 -NotePropertyValue $directorySnapshotParts[1] -Force | Out-Null
    }} else {{
        $cleanupIdentity = [{native_class_name}]::GetIdentity($target.Path, $false)
    }}
    $target | Add-Member -NotePropertyName CleanupIdentity -NotePropertyValue $cleanupIdentity -Force | Out-Null
}}

$directoryTargets = @($cleanTargets | Where-Object {{ [bool]$_.IsDirectory }})
if ($directoryTargets.Count -gt 0) {{
    $previewLimit = 12
    Write-Host "`nPreview of files and folders inside each selected folder (up to 12):" -ForegroundColor Cyan
    foreach ($target in $directoryTargets) {{
        Write-Host "  [$($target.Index)] $($target.Path)" -ForegroundColor White
        if ($target.SelectedNestedPaths.Count -gt 0) {{
            Write-Host "    Explicitly selected nested items included with this folder:" -ForegroundColor Green
            foreach ($selectedNestedPath in $target.SelectedNestedPaths) {{
                Write-Host "      $selectedNestedPath" -ForegroundColor Green
            }}
        }}
        $nestedCautionPaths = @($target.PreservePaths | Where-Object {{ Test-Path -LiteralPath $_ }})
        if ($nestedCautionPaths.Count -gt 0) {{
            Write-Host "    Higher-risk files and folders inside this folder will be kept:" -ForegroundColor Yellow
            foreach ($nestedCautionPath in ($nestedCautionPaths | Select-Object -First $previewLimit)) {{
                Write-Host "      $nestedCautionPath" -ForegroundColor Yellow
            }}
            if ($nestedCautionPaths.Count -gt $previewLimit) {{
                Write-Host "      Additional files and folders that need careful review will also be kept." -ForegroundColor Yellow
            }}
        }}
        $previewEntries = @(Get-ChildItem -LiteralPath $target.Path -Force -EA Stop | Select-Object -First ($previewLimit + 1))
        if ($previewEntries.Count -eq 0) {{
            Write-Host "    (empty)" -ForegroundColor Gray
            continue
        }}
        $hasMoreEntries = $previewEntries.Count -gt $previewLimit
        foreach ($entry in ($previewEntries | Select-Object -First $previewLimit)) {{
            $entryType = if ($entry.PSIsContainer) {{ "folder" }} else {{ "file" }}
            $entrySize = if ($entry.PSIsContainer) {{ "" }} else {{ " - $([long]$entry.Length) B" }}
            Write-Host ("    [{{0}}] {{1}}{{2}}" -f $entryType, $entry.Name, $entrySize) -ForegroundColor Gray
        }}
        if ($hasMoreEntries) {{ Write-Host "    Preview limited to 12 direct items. Other contents may also be removed unless they are protected, project data, or higher-risk candidates." -ForegroundColor Gray }}
    }}
}}

Write-Host "Use -PreviewOnly to list every eligible path after the safety checks without creating a backup or removing anything." -ForegroundColor Gray

if ($ManualReviewOnly) {{
    Write-Host "`nSelected targets (individual files only):" -ForegroundColor Cyan
}} else {{
    Write-Host "`nSelected targets (folder contents are included, except protected and project data and higher-risk candidates you did not explicitly select):" -ForegroundColor Cyan
}}
foreach ($target in $cleanTargets) {{ Write-Host "  [$($target.Index)] $($target.ItemType) | $($target.Path) - $($target.Size)" }}
$backupEnabled = $false
if (-not $PreviewOnly -and $CreateBackup) {{
    $backupEnabled = $true
}} elseif (-not $PreviewOnly -and $SkipBackup) {{
    $backupEnabled = $false
}} elseif (-not $PreviewOnly -and $Force) {{
    $backupEnabled = $false
}} elseif (-not $PreviewOnly -and -not $Force) {{
    $backupAnswer = (Read-Host "Create a verified backup of these selected items first? [y/N]").Trim()
    if ($backupAnswer -match '^(y|yes)$') {{
        $backupEnabled = $true
    }} elseif ($backupAnswer -eq "" -or $backupAnswer -match '^(n|no)$') {{
        $backupEnabled = $false
    }} else {{
        Write-Host "Choose Y or N. Nothing was changed." -ForegroundColor Yellow
        exit 0
    }}
}}
if ($PreviewOnly) {{
    Write-Host "`nPreview-only mode: no recovery backup will be created and no files or folders will be removed." -ForegroundColor Cyan
}} elseif ($backupEnabled) {{
    Write-Host "A verified recovery backup will be created before cleanup." -ForegroundColor Gray
}} else {{
    Write-Host "No backup will be created. If cleanup removes data, Drive Cleanr cannot restore it." -ForegroundColor Yellow
}}
if (-not $PreviewOnly -and -not $Force) {{
    if ($backupEnabled) {{
        if ($ManualReviewOnly) {{
            $confirmPrompt = "Type CLEAN to back up and remove only the selected individual files; verify that you recognize and no longer need them"
        }} else {{
            $confirmPrompt = "Type CLEAN to back up and remove selected items, including folder contents except protected or project data and higher-risk candidates you did not explicitly select"
        }}
        $confirm = Read-Host $confirmPrompt
        if ($confirm -cne "CLEAN") {{ Write-Host "Cancelled; nothing was changed." -ForegroundColor Yellow; exit 0 }}
    }} else {{
        if ($ManualReviewOnly) {{
            $confirmPrompt = "Type DELETE WITHOUT BACKUP to permanently remove only the selected individual files; verify that you recognize and no longer need them"
        }} else {{
            $confirmPrompt = "Type DELETE WITHOUT BACKUP to permanently remove selected items, including folder contents except protected or project data and higher-risk candidates you did not explicitly select"
        }}
        $confirm = Read-Host $confirmPrompt
        if ($confirm -cne "DELETE WITHOUT BACKUP") {{ Write-Host "Cancelled; nothing was changed." -ForegroundColor Yellow; exit 0 }}
    }}
}}

$backup = $null
$backupScript = $null
$recoveryNote = "No recovery backup was created."
if ($backupEnabled) {{
    $recoveryNote = "A verified backup will be retained for recovery."
    $backupScript = Join-Path $PSScriptRoot 'backup.py'
    if (-not (Test-Path -LiteralPath $backupScript)) {{
        $backupScript = {backup_script_literal}
    }}
    if (-not (Test-Path -LiteralPath $backupScript)) {{
        throw "Required backup tool is missing: $backupScript"
    }}
    $backupPaths = @($cleanTargets | ForEach-Object {{ $_.Path }})
    Write-Host "`nCreating backup before cleanup..." -ForegroundColor Cyan
    $backupOutput = & python $backupScript create --priority {priority_arg} --paths $backupPaths --json
    if ($LASTEXITCODE -ne 0) {{ throw "Backup failed. No cleanup was performed." }}
    try {{ $backup = ($backupOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop }}
    catch {{
        $parseError = $_.Exception.Message -replace '[\r\n]+', ' '
        throw "Could not verify the backup result: $parseError. No cleanup was performed."
    }}
    if ($backup.status -ne 'completed' -or $backup.items.Count -ne $cleanTargets.Count) {{
        throw "Backup was incomplete. No cleanup was performed. Review backup $($backup.id)."
    }}
    Write-Host "Backup created: $($backup.id)" -ForegroundColor Green
    if ($backup.backup_root) {{
        $backupLocation = Join-Path $backup.backup_root $backup.id
        Write-Host "Backup saved to: $backupLocation" -ForegroundColor Green
    }}
    $recoveryNote = "Backup $($backup.id) is retained for recovery."
}} else {{
    $recoveryNote = "No backup was created; removed items cannot be restored by Drive Cleanr."
}}

if ($PreviewOnly) {{
    Write-Host "`nStarting read-only preview..." -ForegroundColor Cyan
}} else {{
    Write-Host "`nStarting cleanup..." -ForegroundColor Cyan
}}

$totalFilesRemoved = 0
$totalFoldersRemoved = 0
$totalBytesRemoved = [decimal]0
$cleanupFailed = $false
$previewFileCount = 0
$previewFolderCount = 0
$previewByteCount = [decimal]0
$previewPathsSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$cleanupItemIndex = 0
foreach ($target in $cleanTargets) {{
    $cleanupItemIndex++
    $previousItemStatus = if ($PreviewOnly) {{
        "Preview only; nothing will be removed."
    }} elseif ($cleanupItemIndex -eq 1) {{
        "Nothing has been removed yet."
    }} else {{
        "Files from earlier selected items may already have been removed."
    }}
    Write-Host "`nChecking selected item $cleanupItemIndex of $($cleanTargets.Count): $($target.ItemType) | $($target.Name) | $($target.Path). $previousItemStatus" -ForegroundColor Cyan
    if (-not (Test-Path -LiteralPath $target.Path)) {{
        Write-Host " [Skipped]" -ForegroundColor Gray
        continue
    }}
    $targetFilesPlanned = 0
    $targetFilesRemoved = 0
    $targetFoldersRemoved = 0
    $targetBytesRemoved = [decimal]0
    $targetRemovalCountsAdded = $false
    try {{
        Assert-TargetMatchesScan $target
        if (Test-PathInsideProject $target.Path ([bool]$target.IsDirectory) $true) {{
            throw "The target is now inside a project or an unreadable folder; refusing cleanup: $($target.Path)"
        }}
        $item = Get-Item -LiteralPath $target.Path -Force -EA Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{
            throw "Refusing to remove a reparse point or junction"
        }}
        if ([bool]$item.PSIsContainer -ne [bool]$target.IsDirectory) {{
            throw "The item type changed since the scan; rescan before cleanup"
        }}
        if ($item.PSIsContainer) {{
            Write-Host "Checking this folder's identity and extra Windows file data before cleanup; this check does not remove files." -ForegroundColor Gray
            $targetStreamProgressAction = New-CleanupHashProgressAction $cleanupItemIndex $cleanTargets.Count "folder"
            $currentTargetSnapshot = [{native_class_name}]::GetDirectoryIdentityAndStreamsHash($target.Path, $targetStreamProgressAction)
            $currentTargetSnapshotParts = $currentTargetSnapshot -split '\\|', 2
            if ($currentTargetSnapshotParts.Count -ne 2 -or
                $currentTargetSnapshotParts[0] -ne $target.CleanupIdentity -or
                $currentTargetSnapshotParts[1] -ne $target.CleanupStreamsSha256) {{
                throw "The selected folder was replaced after review; refusing cleanup: $($target.Path)"
            }}
            Write-Host "Reviewing files and folders inside this selection; large folders can take a while. This review does not remove files." -ForegroundColor Gray
            $entries = [System.Collections.Generic.List[System.IO.FileSystemInfo]]::new()
            $folderReviewWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $lastFolderReviewNoticeSeconds = 0
            Get-ChildItem -LiteralPath $target.Path -Recurse -Force -EA Stop | ForEach-Object {{
                [void]$entries.Add($_)
                $elapsedFolderReviewSeconds = [int]$folderReviewWatch.Elapsed.TotalSeconds
                if ($entries.Count -eq 1 -or ($entries.Count % 100) -eq 0 -or
                    ($elapsedFolderReviewSeconds - $lastFolderReviewNoticeSeconds) -ge 10) {{
                    $inventoryStatus = if ($entries.Count -eq 1) {{
                        "First item listed; this review does not remove files."
                    }} else {{
                        "$($entries.Count) files and folders listed; this review does not remove files."
                    }}
                    Write-Progress -Activity "Reviewing selected folder contents" -Status $inventoryStatus
                    Write-Host "  Folder review: $inventoryStatus" -ForegroundColor Gray
                    $lastFolderReviewNoticeSeconds = $elapsedFolderReviewSeconds
                }}
            }}
            Write-Progress -Activity "Reviewing selected folder contents" -Completed
            Write-Host "Folder review complete; $($entries.Count) files and folders found." -ForegroundColor Gray
            $reparseEntry = $entries | Where-Object {{ ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }} | Select-Object -First 1
            if ($reparseEntry) {{ throw "Refusing to clean a directory tree containing a reparse point: $($reparseEntry.FullName)" }}
            # Preserve excluded paths and nested projects even when the user
            # selected a parent folder that contains them.
            $targetRoot = [System.IO.Path]::GetFullPath($target.Path).TrimEnd('\\') + '\\'
            $targetRootPath = $targetRoot.TrimEnd('\\')
            $protectedRoots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($preservePath in $target.PreservePaths) {{
                $normalizedPreservePath = [System.IO.Path]::GetFullPath($preservePath)
                if ($normalizedPreservePath.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {{
                    [void]$protectedRoots.Add($normalizedPreservePath.TrimEnd('\\'))
                }}
            }}
            Write-Host "Checking folder contents for project files and protected data; this check does not remove files." -ForegroundColor Gray
            $projectContentCheckIndex = 0
            foreach ($entry in $entries) {{
                $projectContentCheckIndex++
                $protectedRoot = Get-CleanupProtectedRoot $entry.FullName $entry.Name ([bool]$entry.PSIsContainer)
                if ($protectedRoot) {{
                    # Keep only the outermost protected root to avoid a large
                    # list when the scanner reports every descendant.
                    $ancestor = $protectedRoot
                    $alreadyProtected = $false
                    while ($ancestor.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {{
                        if ($protectedRoots.Contains($ancestor.TrimEnd('\\'))) {{ $alreadyProtected = $true; break }}
                        $parent = [System.IO.Directory]::GetParent($ancestor)
                        if (-not $parent) {{ break }}
                        $ancestor = $parent.FullName
                    }}
                    if (-not $alreadyProtected) {{ [void]$protectedRoots.Add($protectedRoot.TrimEnd('\\')) }}
                }}
                if ($projectContentCheckIndex -eq 1 -or ($projectContentCheckIndex % 100) -eq 0 -or
                    $projectContentCheckIndex -eq $entries.Count) {{
                    $projectContentStatus = "$projectContentCheckIndex of $($entries.Count) items checked for project files; this check does not remove files."
                    Write-Progress -Activity "Checking for project files in this folder" -Status $projectContentStatus -PercentComplete ([int](100 * $projectContentCheckIndex / $entries.Count))
                    Write-Host "  Project file check: $projectContentStatus" -ForegroundColor Gray
                }}
            }}
            Write-Progress -Activity "Checking for project files in this folder" -Completed
            Write-Host "Project file check complete; $projectContentCheckIndex items reviewed." -ForegroundColor Gray
            $preservePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $protectedContentCheckIndex = 0
            foreach ($entry in $entries) {{
                $protectedContentCheckIndex++
                $ancestor = $entry.FullName
                $isProtected = $false
                while ($ancestor.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {{
                    if ($protectedRoots.Contains($ancestor.TrimEnd('\\'))) {{ $isProtected = $true; break }}
                    $parent = [System.IO.Directory]::GetParent($ancestor)
                    if (-not $parent) {{ break }}
                    $ancestor = $parent.FullName
                }}
                if ($isProtected) {{
                    $current = $entry.FullName
                    while ($current.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {{
                        [void]$preservePaths.Add($current)
                        $parent = [System.IO.Directory]::GetParent($current)
                        if (-not $parent) {{ break }}
                        $current = $parent.FullName
                    }}
                    [void]$preservePaths.Add($targetRootPath)
                }}
                if ($protectedContentCheckIndex -eq 1 -or ($protectedContentCheckIndex % 100) -eq 0 -or
                    $protectedContentCheckIndex -eq $entries.Count) {{
                    $protectedContentStatus = "$protectedContentCheckIndex of $($entries.Count) items checked for protected data; this check does not remove files."
                    Write-Progress -Activity "Checking for protected data in this folder" -Status $protectedContentStatus -PercentComplete ([int](100 * $protectedContentCheckIndex / $entries.Count))
                    Write-Host "  Protected-data check: $protectedContentStatus" -ForegroundColor Gray
                }}
            }}
            Write-Progress -Activity "Checking for protected data in this folder" -Completed
            Write-Host "Protected-data check complete; $protectedContentCheckIndex items reviewed." -ForegroundColor Gray
            $deletable = @($entries | Where-Object {{
                -not $preservePaths.Contains($_.FullName)
            }})
            $fileHashTotal = @($deletable | Where-Object {{ -not $_.PSIsContainer }}).Count
            $targetFilesPlanned = $fileHashTotal
            $fileHashIndex = 0
            $folderHashTotal = @($deletable | Where-Object {{ $_.PSIsContainer }}).Count
            $folderHashIndex = 0
            $folderHashWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $lastFolderHashNoticeSeconds = 0
            $fileHashWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $lastFileHashNoticeSeconds = 0
            if ($fileHashTotal -gt 0) {{
                Write-Host "Checking the contents of $fileHashTotal selected files; large files may take a while." -ForegroundColor Gray
            }}
            foreach ($entry in $deletable) {{
                if ($entry.PSIsContainer) {{
                    $folderHashIndex++
                    $elapsedFolderHashSeconds = [int]$folderHashWatch.Elapsed.TotalSeconds
                    if ($folderHashIndex -eq 1 -or ($folderHashIndex % 100) -eq 0 -or
                        $folderHashIndex -eq $folderHashTotal -or
                        ($elapsedFolderHashSeconds - $lastFolderHashNoticeSeconds) -ge 10) {{
                        $folderHashStatus = "Checking folder $folderHashIndex of $folderHashTotal; this check does not remove files."
                        Write-Progress -Activity "Checking selected folder contents" -Status $folderHashStatus -PercentComplete ([int](100 * $folderHashIndex / $folderHashTotal))
                        Write-Host "  $folderHashStatus" -ForegroundColor Gray
                        $lastFolderHashNoticeSeconds = $elapsedFolderHashSeconds
                    }}
                    $folderHashProgressAction = New-CleanupHashProgressAction $folderHashIndex $folderHashTotal "folder"
                    $entrySnapshot = [{native_class_name}]::GetDirectoryIdentityAndStreamsHash($entry.FullName, $folderHashProgressAction)
                    $entrySnapshotParts = $entrySnapshot -split '\\|', 2
                    if ($entrySnapshotParts.Count -ne 2) {{
                        throw "Could not verify a selected folder's identity and named data streams: $($entry.FullName)"
                    }}
                    Add-Member -InputObject $entry -NotePropertyName CleanupIdentity -NotePropertyValue $entrySnapshotParts[0] -Force
                    Add-Member -InputObject $entry -NotePropertyName CleanupStreamsSha256 -NotePropertyValue $entrySnapshotParts[1] -Force
                }} else {{
                    $fileHashIndex++
                    $hashStatus = "Checking file $fileHashIndex of $fileHashTotal; this check does not remove files"
                    Write-Progress -Activity "Checking selected file contents" -Status $hashStatus -PercentComplete ([int](100 * ($fileHashIndex - 1) / $fileHashTotal))
                    if ($fileHashIndex -eq 1) {{
                        Write-Host "  Checking selected file 1 of $fileHashTotal; this check does not remove files." -ForegroundColor Gray
                    }}
                    $entry.Refresh()
                    Add-Member -InputObject $entry -NotePropertyName CleanupLength -NotePropertyValue ([long]$entry.Length) -Force
                    Add-Member -InputObject $entry -NotePropertyName CleanupLastWriteTimeUtcFileTime -NotePropertyValue ([long]$entry.LastWriteTimeUtc.ToFileTimeUtc()) -Force
                    $hashProgressAction = New-CleanupHashProgressAction $fileHashIndex $fileHashTotal
                    $entrySnapshot = [{native_class_name}]::GetFileIdentityAndHash($entry.FullName, $hashProgressAction)
                    $snapshotParts = $entrySnapshot -split '\\|', 2
                    if ($snapshotParts.Count -ne 2) {{
                        throw "Could not verify a selected file's identity and contents: $($entry.FullName)"
                    }}
                    Add-Member -InputObject $entry -NotePropertyName CleanupIdentity -NotePropertyValue $snapshotParts[0] -Force
                    $entry.Refresh()
                    $currentEntryLastWriteTimeUtcFileTime = [long]$entry.LastWriteTimeUtc.ToFileTimeUtc()
                    if ([long]$entry.Length -ne [long]$entry.CleanupLength -or
                        $currentEntryLastWriteTimeUtcFileTime -ne [long]$entry.CleanupLastWriteTimeUtcFileTime) {{
                        throw "A cleanup file changed while its contents were checked; refusing cleanup: $($entry.FullName)"
                    }}
                    Add-Member -InputObject $entry -NotePropertyName CleanupSha256 -NotePropertyValue $snapshotParts[1] -Force
                    Write-Progress -Activity "Checking selected file contents" -Status "File $fileHashIndex of $fileHashTotal checked; this pass does not remove files" -PercentComplete ([int](100 * $fileHashIndex / $fileHashTotal))
                    $elapsedHashSeconds = [int]$fileHashWatch.Elapsed.TotalSeconds
                    if (($fileHashIndex % 100) -eq 0 -or $fileHashIndex -eq $fileHashTotal -or
                        ($elapsedHashSeconds - $lastFileHashNoticeSeconds) -ge 10) {{
                        Write-Host "  Checked $fileHashIndex of $fileHashTotal selected files; this check does not remove files." -ForegroundColor Gray
                        $lastFileHashNoticeSeconds = $elapsedHashSeconds
                    }}
                }}
            }}
            if ($fileHashTotal -gt 0) {{ Write-Progress -Activity "Checking selected file contents" -Completed }}
            if ($folderHashTotal -gt 0) {{ Write-Progress -Activity "Checking selected folder contents" -Completed }}
            $previewFolderDataBytes = $null
            if ($PreviewOnly) {{
                $previewDirectorySeparators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
                $previewTargetPath = [System.IO.Path]::GetFullPath($target.Path).TrimEnd($previewDirectorySeparators)
                $previewFolderDataBytes = [System.Collections.Generic.Dictionary[string, decimal]]::new([System.StringComparer]::OrdinalIgnoreCase)
                $previewFolderDataBytes[$previewTargetPath] = [decimal]0
                $previewDirectories = @($entries | Where-Object {{ $_.PSIsContainer }} | Sort-Object {{ $_.FullName.Length }} -Descending)
                $previewSizeWorkTotal = [long]$entries.Count + [long]$deletable.Count + [long]$previewDirectories.Count
                $previewSizeWorkIndex = 0
                foreach ($entry in $entries) {{
                    if ($entry.PSIsContainer) {{
                        $previewDirectoryPath = [System.IO.Path]::GetFullPath($entry.FullName).TrimEnd($previewDirectorySeparators)
                        $previewFolderDataBytes[$previewDirectoryPath] = [decimal]0
                    }}
                    $previewSizeWorkIndex++
                    Write-PreviewFolderSizeProgress $previewSizeWorkIndex $previewSizeWorkTotal
                }}
                foreach ($entry in $deletable) {{
                    if (-not $entry.PSIsContainer) {{
                        $previewFilePath = [System.IO.Path]::GetFullPath($entry.FullName)
                        $previewFileParent = [System.IO.Directory]::GetParent($previewFilePath)
                        if (-not $previewFileParent -or -not $previewFolderDataBytes.ContainsKey($previewFileParent.FullName)) {{
                            throw "Could not safely total eligible file data for this folder preview."
                        }}
                        $previewFolderDataBytes[$previewFileParent.FullName] += [decimal]$entry.CleanupLength
                    }}
                    $previewSizeWorkIndex++
                    Write-PreviewFolderSizeProgress $previewSizeWorkIndex $previewSizeWorkTotal
                }}
                foreach ($entry in $previewDirectories) {{
                    $previewDirectoryPath = [System.IO.Path]::GetFullPath($entry.FullName).TrimEnd($previewDirectorySeparators)
                    $previewDirectoryParent = [System.IO.Directory]::GetParent($previewDirectoryPath)
                    if (-not $previewDirectoryParent -or -not $previewFolderDataBytes.ContainsKey($previewDirectoryParent.FullName)) {{
                        throw "Could not safely total eligible file data for this folder preview."
                    }}
                    $previewFolderDataBytes[$previewDirectoryParent.FullName] += [decimal]$previewFolderDataBytes[$previewDirectoryPath]
                    $previewSizeWorkIndex++
                    Write-PreviewFolderSizeProgress $previewSizeWorkIndex $previewSizeWorkTotal
                }}
                if ($previewSizeWorkTotal -gt 0) {{
                    Write-Progress -Activity "Summarizing eligible folder sizes" -Completed
                }}
            }}
            if ($backupEnabled) {{
                $verifyOutput = & python $backupScript verify --id $backup.id --paths $target.Path
                if ($LASTEXITCODE -ne 0) {{ throw "The target changed after backup or its backup could not be verified; refusing cleanup." }}
            }}
            Assert-TargetMatchesScan $target
            Write-Host "Rechecking this folder's identity and extra Windows file data before cleanup; this check does not remove files." -ForegroundColor Gray
            $verifiedTargetProgressAction = New-CleanupHashProgressAction $cleanupItemIndex $cleanTargets.Count "folder"
            $verifiedTargetSnapshot = [{native_class_name}]::GetDirectoryIdentityAndStreamsHash($target.Path, $verifiedTargetProgressAction)
            $verifiedTargetSnapshotParts = $verifiedTargetSnapshot -split '\\|', 2
            if ($verifiedTargetSnapshotParts.Count -ne 2 -or
                $verifiedTargetSnapshotParts[0] -ne $target.CleanupIdentity -or
                $verifiedTargetSnapshotParts[1] -ne $target.CleanupStreamsSha256) {{
                throw "The selected folder or its named data streams changed after review; refusing cleanup: $($target.Path)"
            }}
            if (Test-PathInsideProject $target.Path $true $true) {{
                throw "The target is now inside a project or an unreadable folder; refusing cleanup: $($target.Path)"
            }}
            Write-Host "Rechecking the selected folder for project files and protected data before cleanup; this check does not remove files." -ForegroundColor Gray
            $freshProjectCheckIndex = 0
            $freshProjectCheckWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $lastFreshProjectNoticeSeconds = 0
            $projectCheckDirectories = [System.Collections.Generic.Stack[string]]::new()
            $projectCheckDirectories.Push($target.Path)
            while ($projectCheckDirectories.Count -gt 0) {{
                $directoryToCheck = $projectCheckDirectories.Pop()
                foreach ($entryPath in [System.IO.Directory]::EnumerateFileSystemEntries($directoryToCheck)) {{
                    $freshProjectCheckIndex++
                    $entryAttributes = [System.IO.File]::GetAttributes($entryPath)
                    if (($entryAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{
                        throw "A reparse point appeared after cleanup review; refusing cleanup: $entryPath"
                    }}
                    $entryName = [System.IO.Path]::GetFileName($entryPath)
                    $entryIsDirectory = ($entryAttributes -band [IO.FileAttributes]::Directory) -ne 0
                    $freshProtectedRoot = Get-CleanupProtectedRoot $entryPath $entryName $entryIsDirectory
                    if ($freshProtectedRoot) {{
                        $ancestor = $freshProtectedRoot
                        $alreadyProtected = $false
                        while ($ancestor.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {{
                            if ($protectedRoots.Contains($ancestor.TrimEnd('\\'))) {{ $alreadyProtected = $true; break }}
                            $parent = [System.IO.Directory]::GetParent($ancestor)
                            if (-not $parent) {{ break }}
                            $ancestor = $parent.FullName
                        }}
                        if (-not $alreadyProtected) {{
                            throw "A project marker or protected path appeared after cleanup review; refusing cleanup: $freshProtectedRoot"
                        }}
                    }}
                    if ($entryIsDirectory) {{ $projectCheckDirectories.Push($entryPath) }}
                    $elapsedFreshProjectSeconds = [int]$freshProjectCheckWatch.Elapsed.TotalSeconds
                    if ($freshProjectCheckIndex -eq 1 -or ($freshProjectCheckIndex % 100) -eq 0 -or
                        ($elapsedFreshProjectSeconds - $lastFreshProjectNoticeSeconds) -ge 10) {{
                        $freshProjectStatus = "$freshProjectCheckIndex items rechecked for project files; this check does not remove files."
                        Write-Progress -Activity "Rechecking project and protected paths" -Status $freshProjectStatus
                        Write-Host "  Final project check: $freshProjectStatus" -ForegroundColor Gray
                        $lastFreshProjectNoticeSeconds = $elapsedFreshProjectSeconds
                    }}
                }}
            }}
            Write-Progress -Activity "Rechecking project and protected paths" -Completed
            Write-Host "Final project check complete; $freshProjectCheckIndex items rechecked." -ForegroundColor Gray
            $orderedDeletable = @($deletable | Sort-Object {{ $_.FullName.Length }} -Descending)
            $fileRecheckTotal = @($orderedDeletable | Where-Object {{ -not $_.PSIsContainer }}).Count
            $folderRecheckTotal = @($orderedDeletable | Where-Object {{ $_.PSIsContainer }}).Count
            if ($PreviewOnly) {{
                Write-Host "Eligible contents that would be removed if cleanup is started:" -ForegroundColor Cyan
                foreach ($entry in $orderedDeletable) {{
                    Assert-CleanupEntryPathWithinSelection $target $entry
                    $previewPath = [System.IO.Path]::GetFullPath($entry.FullName)
                    if (-not $previewPathsSeen.Add($previewPath)) {{ continue }}
                    if ($entry.PSIsContainer) {{
                        $previewFolderCount++
                        $previewFolderKey = $previewPath.TrimEnd($previewDirectorySeparators)
                        $folderDataSize = Format-PreviewFileDataSize $previewFolderDataBytes[$previewFolderKey]
                        Write-Host "  Would remove | Folder | $previewPath | $folderDataSize of eligible file data below (includes nested folders)"
                    }} else {{
                        $previewLength = [long]$entry.CleanupLength
                        $previewFileCount++
                        $previewByteCount += [decimal]$previewLength
                        Write-Host "  Would remove | File | $previewPath | $previewLength bytes"
                    }}
                }}
                if ($preservePaths.Count -eq 0) {{
                    $previewRoot = [System.IO.Path]::GetFullPath($target.Path)
                    if ($previewPathsSeen.Add($previewRoot)) {{
                        $previewFolderCount++
                        $rootDataSize = Format-PreviewFileDataSize $previewFolderDataBytes[$previewTargetPath]
                        Write-Host "  Would remove | Folder | $previewRoot | $rootDataSize of eligible file data below (includes nested folders)"
                    }}
                }} else {{
                    $keptRootDataSize = Format-PreviewFileDataSize $previewFolderDataBytes[$previewTargetPath]
                    Write-Host "  Keep selected folder | Protected data will remain inside it | $keptRootDataSize of eligible file data below"
                }}
                continue
            }}
            $fileRecheckIndex = 0
            $folderRecheckIndex = 0
            $folderRemovalWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $lastFolderRemovalNoticeSeconds = 0
            $fileRemovalWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $lastFileRemovalNoticeSeconds = 0
            if ($fileRecheckTotal -gt 0) {{
                Write-Host "Initial checks passed. Now checking and removing selected files one at a time; earlier files may already be removed if a later check fails." -ForegroundColor Yellow
            }}
            foreach ($entry in $orderedDeletable) {{
                if (-not $entry.PSIsContainer) {{
                    $fileRecheckIndex++
                    Write-Progress -Activity "Removing selected files" -Status "Processing file $fileRecheckIndex of $fileRecheckTotal; earlier files may already be removed" -PercentComplete ([int](100 * ($fileRecheckIndex - 1) / $fileRecheckTotal))
                }} else {{
                    $folderRecheckIndex++
                    $elapsedFolderRemovalSeconds = [int]$folderRemovalWatch.Elapsed.TotalSeconds
                    if ($folderRecheckIndex -eq 1 -or ($folderRecheckIndex % 100) -eq 0 -or
                        $folderRecheckIndex -eq $folderRecheckTotal -or
                        ($elapsedFolderRemovalSeconds - $lastFolderRemovalNoticeSeconds) -ge 10) {{
                        $folderRemovalStatus = "Checking folder $folderRecheckIndex of $folderRecheckTotal before removal; earlier files may already have been removed."
                        Write-Progress -Activity "Removing selected folders" -Status $folderRemovalStatus -PercentComplete ([int](100 * $folderRecheckIndex / $folderRecheckTotal))
                        Write-Host "  $folderRemovalStatus" -ForegroundColor Gray
                        $lastFolderRemovalNoticeSeconds = $elapsedFolderRemovalSeconds
                    }}
                }}
                Assert-CleanupEntryPathWithinSelection $target $entry
                if ($entry.PSIsContainer) {{
                    $folderRemovalProgressAction = New-CleanupHashProgressAction $folderRecheckIndex $folderRecheckTotal "folder"
                    [{native_class_name}]::DeleteEmptyDirectoryIfUnchanged(
                        $entry.FullName, [string]$entry.CleanupIdentity, [string]$entry.CleanupStreamsSha256,
                        $folderRemovalProgressAction)
                    $targetFoldersRemoved++
                }} else {{
                    $fileRemovalProgressAction = New-CleanupHashProgressAction $fileRecheckIndex $fileRecheckTotal "file"
                    [{native_class_name}]::DeleteFileIfUnchanged(
                        $entry.FullName, [string]$entry.CleanupIdentity, [string]$entry.CleanupSha256,
                        [long]$entry.CleanupLength, [long]$entry.CleanupLastWriteTimeUtcFileTime,
                        $fileRemovalProgressAction)
                    $targetFilesRemoved++
                    $targetBytesRemoved += [decimal]$entry.CleanupLength
                    $elapsedRemovalSeconds = [int]$fileRemovalWatch.Elapsed.TotalSeconds
                    if ($targetFilesRemoved -eq 1 -or ($targetFilesRemoved % 100) -eq 0 -or
                        $targetFilesRemoved -eq $fileRecheckTotal -or
                        ($elapsedRemovalSeconds - $lastFileRemovalNoticeSeconds) -ge 10) {{
                        Write-Host "  Removed $targetFilesRemoved of $fileRecheckTotal selected files from this item." -ForegroundColor Gray
                        $lastFileRemovalNoticeSeconds = $elapsedRemovalSeconds
                    }}
                }}
            }}
            if ($fileRecheckTotal -gt 0) {{ Write-Progress -Activity "Removing selected files" -Completed }}
            if ($folderRecheckTotal -gt 0) {{ Write-Progress -Activity "Removing selected folders" -Completed }}
            if ($preservePaths.Count -gt 0) {{
                Write-Host " [Partially cleaned; protected data was preserved]" -ForegroundColor Yellow
            }} else {{
                # Delete only an empty root. A new child may have appeared after
                # the earlier enumeration; recursive removal here could erase
                # data that was never included in the reviewed cleanup snapshot.
                Write-Host "Checking the selected folder's extra Windows file data before final removal; this check does not remove files." -ForegroundColor Gray
                $rootRemovalProgressAction = New-CleanupHashProgressAction $cleanupItemIndex $cleanTargets.Count "folder"
                [{native_class_name}]::DeleteEmptyDirectoryIfUnchanged(
                    $target.Path, [string]$target.CleanupIdentity, [string]$target.CleanupStreamsSha256,
                    $rootRemovalProgressAction)
                $targetFoldersRemoved++
            }}
        }} else {{
            $targetFilesPlanned = 1
            Write-Host "Rechecking selected file contents before removal..." -ForegroundColor Gray
            Write-Progress -Activity "Checking selected file contents" -Status "Comparing file contents" -PercentComplete 50
            $cleanupLength = [long]$item.Length
            $cleanupLastWriteTimeUtcFileTime = [long]$item.LastWriteTimeUtc.ToFileTimeUtc()
            $hashProgressAction = New-CleanupHashProgressAction 1 1
            $fileSnapshot = [{native_class_name}]::GetFileIdentityAndHash($target.Path, $hashProgressAction)
            $snapshotParts = $fileSnapshot -split '\\|', 2
            if ($snapshotParts.Count -ne 2 -or $snapshotParts[0] -ne $target.CleanupIdentity) {{
                throw "The selected file was replaced while its contents were checked; refusing cleanup: $($target.Path)"
            }}
            $cleanupHash = $snapshotParts[1]
            Write-Progress -Activity "Checking selected file contents" -Completed
            if ($backupEnabled) {{
                $verifyOutput = & python $backupScript verify --id $backup.id --paths $target.Path
                if ($LASTEXITCODE -ne 0) {{ throw "The target changed after backup or its backup could not be verified; refusing cleanup." }}
            }}
            Assert-TargetMatchesScan $target
            if (Test-PathInsideProject $target.Path $false $true) {{
                throw "The target is now inside a project or an unreadable folder; refusing cleanup: $($target.Path)"
            }}
            if ($PreviewOnly) {{
                $previewPath = [System.IO.Path]::GetFullPath($target.Path)
                if ($previewPathsSeen.Add($previewPath)) {{
                    $previewFileCount++
                    $previewByteCount += [decimal]$cleanupLength
                    Write-Host "  Would remove | File | $previewPath | $cleanupLength bytes"
                }}
                continue
            }}
            Write-Progress -Activity "Checking selected file contents" -Status "Confirming and removing the reviewed file" -PercentComplete 50
            $fileRemovalProgressAction = New-CleanupHashProgressAction 1 1 "file"
            [{native_class_name}]::DeleteFileIfUnchanged(
                $target.Path, [string]$target.CleanupIdentity, [string]$cleanupHash,
                [long]$cleanupLength, [long]$cleanupLastWriteTimeUtcFileTime,
                $fileRemovalProgressAction)
            $targetFilesRemoved++
            $targetBytesRemoved += [decimal]$item.Length
            Write-Progress -Activity "Checking selected file contents" -Completed
        }}
        $totalFilesRemoved += $targetFilesRemoved
        $totalFoldersRemoved += $targetFoldersRemoved
        $totalBytesRemoved += $targetBytesRemoved
        $targetRemovalCountsAdded = $true
        $cleanedMB = [math]::Round($targetBytesRemoved / 1MB, 2)
        $targetFilesLabel = if ($targetFilesRemoved -eq 1) {{ "file" }} else {{ "files" }}
        $targetFoldersLabel = if ($targetFoldersRemoved -eq 1) {{ "folder" }} else {{ "folders" }}
        Write-Host " [Done - removed $targetFilesRemoved $targetFilesLabel and $targetFoldersRemoved $targetFoldersLabel; $cleanedMB MB of file data]" -ForegroundColor Green
    }} catch {{
        $cleanupFailed = $true
        $exception = $_.Exception
        while ($exception.InnerException) {{ $exception = $exception.InnerException }}
        if ($exception -is [System.UnauthorizedAccessException]) {{
            $failureReason = "Access was denied"
        }} elseif ($exception -is [System.IO.IOException]) {{
            if ($exception.Message -eq "The selected file's contents changed after backup verification; refusing cleanup") {{
                if ($backupEnabled) {{
                    $failureReason = $exception.Message
                }} else {{
                    $failureReason = "The selected file's contents changed after review; refusing cleanup"
                }}
            }} else {{
            if ($exception.Message -in @(
                "A cleanup path became a reparse point; refusing deletion",
                "A cleanup path changed type; refusing deletion",
                "A cleanup path was replaced after review; refusing deletion",
                "The selected item's named data streams changed after review; refusing cleanup",
                "Named data streams changed while they were being checked; refusing cleanup",
                "Windows refused removal, and the original read-only attribute could not be restored",
                "Drive roots are not valid cleanup targets"
            )) {{
                $failureReason = $exception.Message
            }} else {{
                $failureReason = "The file or folder is unavailable, in use, or changed"
            }}
            }}
        }} elseif ($exception -is [System.Management.Automation.RuntimeException]) {{
            $knownRuntimeFailurePrefixes = @(
                "The target or one of its parent paths is now a reparse point; refusing cleanup:",
                "The item type changed since the scan; rescan before cleanup:",
                "A cleanup entry moved outside its selected folder; refusing cleanup:",
                "A selected target is now inside a project or an unreadable folder; refusing cleanup:",
                "Refusing to remove a reparse point or junction",
                "The selected folder was replaced after review; refusing cleanup:",
                "Refusing to clean a directory tree containing a reparse point:",
                "The selected folder or its named data streams changed after review; refusing cleanup:",
                "A reparse point appeared after cleanup review; refusing cleanup:",
                "A project marker or protected path appeared after cleanup review; refusing cleanup:",
                "Could not verify a selected file's identity and contents:",
                "A cleanup file changed while its contents were checked; refusing cleanup:",
                "The target changed after backup or its backup could not be verified; refusing cleanup.",
                "The selected folder was replaced during cleanup review; refusing cleanup:",
                "The target is now inside a project or an unreadable folder; refusing cleanup:",
                "The selected file was replaced while its contents were checked; refusing cleanup:"
            )
            $knownRuntimeFailure = $false
            foreach ($knownPrefix in $knownRuntimeFailurePrefixes) {{
                if ($exception.Message.StartsWith($knownPrefix, [System.StringComparison]::Ordinal)) {{
                    $knownRuntimeFailure = $true
                    break
                }}
            }}
            if ($knownRuntimeFailure) {{
                $failureReason = $exception.Message
            }} else {{
                $failureReason = "A cleanup check failed; no more files will be removed from this item."
            }}
        }} else {{
            $failureReason = "The operation failed; check the target and available permissions"
        }}
        if (-not $targetRemovalCountsAdded) {{
            $totalFilesRemoved += $targetFilesRemoved
            $totalFoldersRemoved += $targetFoldersRemoved
            $totalBytesRemoved += $targetBytesRemoved
            $targetRemovalCountsAdded = $true
        }}
        if ($PreviewOnly) {{
            Write-Host " [Preview incomplete: $failureReason. Nothing was removed.]" -ForegroundColor Red
        }} elseif ($targetFilesRemoved -gt 0 -or $targetFoldersRemoved -gt 0) {{
            $partialBytes = $targetBytesRemoved.ToString('0')
            Write-Host " [Failed: $failureReason. Removed $targetFilesRemoved of $targetFilesPlanned selected files and $targetFoldersRemoved folders from this item before the error ($partialBytes bytes of file data). $recoveryNote]" -ForegroundColor Red
        }} else {{
            Write-Host " [Failed: $failureReason. No files or folders were removed from this item. $recoveryNote]" -ForegroundColor Red
        }}
    }}
}}

Write-Host "`n========================================" -ForegroundColor Cyan
if ($PreviewOnly) {{
    if ($cleanupFailed) {{
        Write-Host "Preview incomplete. Some selected items could not be checked; nothing was removed." -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Cyan
        exit 1
    }}
    $previewBytesDisplay = $previewByteCount.ToString('0')
    $previewFilesLabel = if ($previewFileCount -eq 1) {{ "file" }} else {{ "files" }}
    $previewFoldersLabel = if ($previewFolderCount -eq 1) {{ "folder" }} else {{ "folders" }}
    Write-Host "Preview complete: $previewFileCount $previewFilesLabel and $previewFolderCount $previewFoldersLabel would be removed ($previewBytesDisplay bytes of file data)." -ForegroundColor Green
    Write-Host "Folder sizes include eligible files in nested folders, so folder rows overlap. The total counts each eligible file once." -ForegroundColor Gray
    Write-Host "This is the total size of eligible files, not a guarantee of space reclaimed; hard links and filesystem behavior can change the amount." -ForegroundColor Gray
    Write-Host "No recovery backup was created and nothing was removed. The cleanup plan will repeat its safety checks if you run it later." -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    exit 0
}}
$totalBytesDisplay = $totalBytesRemoved.ToString('0')
$totalFilesLabel = if ($totalFilesRemoved -eq 1) {{ "file" }} else {{ "files" }}
$totalFoldersLabel = if ($totalFoldersRemoved -eq 1) {{ "folder" }} else {{ "folders" }}
$totalRemovedGB = [math]::Round($totalBytesRemoved / 1GB, 2)
if ($cleanupFailed) {{
    Write-Host "Cleanup finished with errors. Removed $totalFilesRemoved $totalFilesLabel and $totalFoldersRemoved $totalFoldersLabel ($totalBytesDisplay bytes of file data; about $totalRemovedGB GB); some items may remain. $recoveryNote" -ForegroundColor Yellow
    exit 1
}}
Write-Host "Cleanup complete! Removed $totalFilesRemoved $totalFilesLabel and $totalFoldersRemoved $totalFoldersLabel ($totalBytesDisplay bytes of file data; about $totalRemovedGB GB)." -ForegroundColor Green
if (-not $backupEnabled) {{ Write-Host "No recovery backup was created; Drive Cleanr cannot restore removed items." -ForegroundColor Yellow }}
Write-Host "========================================" -ForegroundColor Cyan
'''

    # Build the target list.
    targets_str = ""
    for item in items:
        path = _ps_literal(item["path"])
        item_type = display_item_type(item)
        is_directory = item_type == "Folder"
        preserve_paths = preserved_candidates.get(_path_key(item["path"]), [])
        preserve_paths_str = ", ".join(_ps_literal(value) for value in preserve_paths)
        selected_nested_paths = selected_nested_candidates.get(_path_key(item["path"]), [])
        selected_nested_paths_str = ", ".join(
            _ps_literal(value) for value in selected_nested_paths
        )
        targets_str += f'''    @{{
        Name = {_ps_literal(item['name'])}
        Path = {path}
        Size = {_ps_literal(item['size_formatted'])}
        ItemType = {_ps_literal(item_type)}
        IsDirectory = ${str(is_directory).lower()}
        PreservePaths = @({preserve_paths_str})
        SelectedNestedPaths = @({selected_nested_paths_str})
    }},
'''

    protected_fragments = [re.escape("\\".join(components)) for components in _EXCLUDE_COMPONENTS]
    protected_fragments.extend(re.escape(prefix) + r"[^\\]*" for prefix in EXCLUDE_COMPONENT_PREFIXES)
    protected_pattern = r"(?:^|\\)(?:" + "|".join(protected_fragments) + r")(?:\\|$)"
    project_markers_str = ",\n".join(f"        {_ps_literal(marker)}" for marker in PROJECT_MARKERS)
    project_suffix_pattern = r"(?:" + "|".join(
        re.escape(suffix) for suffix in PROJECT_MARKER_SUFFIXES
    ) + r")$"

    manual_review_only = priority == "manual"
    script = script.format(
        priority_name=priority_name,
        manual_review_only="$true" if manual_review_only else "$false",
        native_class_name=native_class_name,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        scan_file_time=_safe_scan_timestamp(results),
        targets=targets_str.rstrip(",\n"),
        default_selection=default_selection,
        protected_pattern=_ps_literal(protected_pattern),
        project_markers=project_markers_str,
        project_marker_suffix_pattern=_ps_literal(project_suffix_pattern),
        backup_script_literal=backup_script_literal,
        priority_arg=("manual" if priority == "manual" else priority if priority != "all" else "low")
    )
    script = script.replace("__NATIVE_CLEANUP_GUARD__", native_guard)

    # The BOM lets Windows PowerShell 5.1 read Unicode paths correctly.
    with open(output_path, 'x', encoding='utf-8-sig') as f:
        f.write(script)

    return output_path


def write_item_list_report(results, output_path):
    """Write candidates grouped by category to a text file."""
    all_candidate_items = [
        item for category in results["categories"].values() for item in category["items"]
    ]
    manual_review_files = results.get("manual_review_files", [])
    if not isinstance(manual_review_files, list):
        raise ValueError("Manual-review file list is malformed")
    for item in manual_review_files:
        if (not isinstance(item, dict) or item.get("manual_review") is not True or
                not isinstance(item.get("path"), str) or not item["path"] or
                not item["path"].isprintable() or display_item_type(item) != "File" or
                not isinstance(item.get("size_formatted"), str)):
            raise ValueError("Manual-review file list contains a malformed entry")
    _ensure_output_outside_targets(
        output_path, all_candidate_items + manual_review_files
    )
    lines = []
    lines.append("Files and Folders for Cleanup Review")
    lines.append(f"Generated at: {datetime.now().isoformat()}")
    lines.append(f"Source scan last modified: {_safe_scan_timestamp(results)}")
    lines.append("")
    if results.get("reparse_candidate_count", 0):
        lines.append(f"Skipped {results['reparse_candidate_count']} paths that pass through a link or could not be checked.")
        lines.append("")
    if results.get("unsafe_display_path_count", 0):
        lines.append(
            f"Skipped {results['unsafe_display_path_count']} scan entries with hidden or control characters in their paths; they cannot be shown safely for review."
        )
        lines.append("")
    if results.get("temp_root_candidate_count", 0):
        lines.append(f"Known temporary folders skipped: {results['temp_root_candidate_count']}; files and folders inside are shown separately when they match the cleanup rules.")
        lines.append("")
    project_lines = _project_protection_lines(results)
    if project_lines:
        lines.extend(project_lines)
        lines.append("")
    nested_pairs = _nested_candidate_pairs(all_candidate_items)
    lines.extend(_nested_candidate_summary(all_candidate_items, nested_pairs))
    if nested_pairs:
        lines.append(
            "The same space is counted once in the total, even when items appear in different review groups. Each folder row still shows its full size."
        )
    lines.append("")

    all_items = []
    tier_estimates = _tier_size_estimates(results["categories"], nested_pairs)
    for priority in ["high", "medium", "low"]:
        category = results["categories"][priority]
        lines.append("=" * 60)
        lines.append(f"[{category['name']}] - Estimated space: {format_size(tier_estimates[priority])}")
        lines.append("=" * 60)
        if not category["items"]:
            lines.append("(none)")
        else:
            for item in category["items"]:
                all_items.append(item)
                lines.append(f"- {item['size_formatted']}  {display_item_type(item)}  {item['name']}")
                lines.append(f"  {item['path']}")
                risk = "lower risk; review first" if item.get("safe") else "caution; review carefully"
                lines.append(f"  Risk level: {risk}")
        lines.append("")

    lines.append("=" * 60)
    unique_size = sum(item["size"] for item in _non_overlapping_items(all_items))
    lines.append(f"Estimated space in automatic cleanup suggestions (counted once): {format_size(unique_size)}")
    lines.append("Folder totals can include nested protected data, which cleanup preserves.")
    lines.append("Every exact path still requires review; estimates can differ from space actually recovered.")
    if manual_review_files:
        lines.append("")
        lines.append("=" * 60)
        lines.append("Largest files outside automatic cleanup suggestions — manual review only")
        lines.append("These files are not recommendations. Drive Cleanr cannot tell whether they are needed.")
        lines.append("They are excluded from the estimated cleanup space above.")
        lines.append("=" * 60)
        for item in manual_review_files:
            lines.append(f"- {item['size_formatted']}  File  Manual review")
            lines.append(f"  {item['path']}")
    lines.append("=" * 60)

    with open(output_path, "x", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return output_path


def clear_screen():
    """Clear the terminal screen for the interactive UI."""
    os.system("cls" if os.name == "nt" else "clear")


def prompt_choice(prompt, choices, default=None):
    """Read a menu choice, optionally using a default value."""
    suffix = f" [{default}]" if default is not None else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if value in choices:
            return value
        print(f"Please enter one of: {', '.join(choices)}")


def parse_cleanup_selection(answer, item_count):
    """Parse a numbered cleanup selection; blank or Q cancels."""
    if not isinstance(answer, str):
        raise ValueError("Enter item numbers, A, or Q.")
    value = answer.strip()
    if not value or value.casefold() in {"q", "quit", "cancel"}:
        return None
    if value.casefold() in {"a", "all"}:
        if item_count < 1:
            raise ValueError("There are no items to select.")
        return list(range(1, item_count + 1))
    if item_count < 1:
        raise ValueError("There are no items to select.")

    selected = []
    for token in re.split(r"[,;\s]+", value):
        if not token.isdecimal():
            raise ValueError("Enter item numbers separated by commas, A for all listed entries, or Q to cancel.")
        index = int(token)
        if index < 1 or index > item_count:
            raise ValueError(f"Item {index} is not in the list. Choose a number from 1 to {item_count}.")
        if index not in selected:
            selected.append(index)
    return selected


def _folder_browse_skip_lines(results):
    """Summarize why matching scan candidates were kept off the folder list."""
    lines = []
    stale_count = results.get("stale_candidate_count", 0)
    if stale_count:
        lines.append(f"Skipped {stale_count} candidate entries that no longer exist. Rescan to refresh them.")
    lines.extend(_project_protection_lines(results))
    unclassified_count = results.get("unclassified_candidate_count", 0)
    if unclassified_count:
        lines.append(f"Skipped {unclassified_count} entries whose file or folder type could not be confirmed.")
    type_mismatch_count = results.get("type_mismatch_count", 0)
    if type_mismatch_count:
        lines.append(f"Skipped {type_mismatch_count} entries whose type changed since the scan. Rescan to refresh them.")
    reparse_count = results.get("reparse_candidate_count", 0)
    if reparse_count:
        lines.append(f"Skipped {reparse_count} paths that cross a link or could not be checked.")
    unsafe_display_path_count = results.get("unsafe_display_path_count", 0)
    if unsafe_display_path_count:
        lines.append(
            f"Skipped {unsafe_display_path_count} scan entries with hidden or control characters in their paths; they cannot be shown safely for review."
        )
    temp_root_count = results.get("temp_root_candidate_count", 0)
    if temp_root_count:
        lines.append(
            f"Skipped {temp_root_count} recognized temporary folders; matching entries inside are considered separately."
        )
    return lines


def select_manual_review_files(results):
    """Let users choose exact files that were not automatically classified."""
    items = results.get("manual_review_files")
    if not isinstance(items, list):
        raise ValueError("Manual-review file list is missing or malformed")
    if not items:
        print("No large, unclassified files are available for manual review in this scan.")
        return []
    for item in items:
        if (not isinstance(item, dict) or item.get("manual_review") is not True or
                not isinstance(item.get("path"), str) or not item["path"] or
                not item["path"].isprintable() or item.get("name") != MANUAL_REVIEW_LABEL or
                display_item_type(item) != "File" or
                not isinstance(item.get("size"), int) or item["size"] < 0 or
                not isinstance(item.get("size_formatted"), str)):
            raise ValueError("Manual-review list contains a malformed or unsafe file entry")
    if len(items) > MANUAL_REVIEW_FILE_LIMIT:
        items = items[:MANUAL_REVIEW_FILE_LIMIT]

    print("\nLargest files not included in automatic cleanup suggestions:")
    print("Drive Cleanr cannot tell whether these files are needed. Choose only individual files you recognize and no longer need.")
    print("Protected paths and detected projects are omitted. These entries are never selected automatically.")
    selected = {}
    page = 0
    filter_text = ""

    while True:
        filtered_items = [
            item for item in items
            if not filter_text or filter_text in (
                str(item.get("name", "")) + " " + str(item.get("path", ""))
            ).casefold()
        ]
        page_count = max(1, (len(filtered_items) + MANUAL_REVIEW_PAGE_SIZE - 1) // MANUAL_REVIEW_PAGE_SIZE)
        page = min(page, page_count - 1)
        first = page * MANUAL_REVIEW_PAGE_SIZE
        page_items = filtered_items[first:first + MANUAL_REVIEW_PAGE_SIZE]
        print(f"\nFiles shown: {len(filtered_items)} | Page {page + 1} of {page_count}")
        if filter_text:
            print(f"Filter: {filter_text}")
        if not page_items:
            print("No files match this filter.")
        for index, item in enumerate(page_items, start=1):
            path = item.get("path", "")
            marker = "*" if _path_key(path) in selected else " "
            print(f"{marker} [{index}] File | {item.get('size_formatted', 'unknown size')} | Manual review")
            print(f"      {path}")
        print("Enter file numbers to select or clear them. N/P changes page; F filters; D finishes; B cancels.")
        answer = input("Choose files on this page: ").strip()
        command = answer.casefold()
        if command in {"d", "done"}:
            if selected:
                chosen = list(selected.values())
                scan_size = sum(item["size"] for item in chosen)
                print(f"Selected {len(chosen)} individual file(s); scan-reported size: {format_size(scan_size)}.")
                print("Check every selected path before creating a manual-review plan:")
                for item in chosen:
                    print(f"  File | {item['size_formatted']} | {item['path']}")
                return chosen
            print("Choose at least one file, or press B to return without creating a plan.")
            continue
        if command in {"b", "back", "q", "quit", "cancel"}:
            print("Manual review cancelled; no files were added to a cleanup plan.")
            return []
        if command in {"n", "next"}:
            if page + 1 < page_count:
                page += 1
            else:
                print("You are already on the last page.")
            continue
        if command in {"p", "previous", "prev"}:
            if page > 0:
                page -= 1
            else:
                print("You are already on the first page.")
            continue
        if command in {"f", "filter"}:
            filter_text = input("Filter by file name or path (blank clears the filter): ").strip().casefold()
            page = 0
            continue
        if command in {"a", "all"}:
            print("Bulk selection is unavailable for unclassified files. Choose each exact file by number.")
            continue
        try:
            indexes = parse_cleanup_selection(answer, len(page_items))
        except ValueError as exc:
            print(str(exc))
            continue
        if indexes is None:
            print("Enter file numbers, N/P, F, D to finish, or B to cancel.")
            continue
        for index in indexes:
            item = page_items[index - 1]
            key = _path_key(item.get("path", ""))
            if key in selected:
                selected.pop(key)
            else:
                selected[key] = item


def _browse_folder_candidates(csv_file, min_size_mb, folder_entries, priority):
    """Find and let the user choose exact scan entries inside one listed folder."""
    if not folder_entries:
        print("There are no listed folders to browse inside.")
        return []

    print("\nFolders you can inspect for individual scan entries:")
    for index, (candidate_priority, item) in enumerate(folder_entries, start=1):
        print(
            f"  [{index}] {CLEANABLE_PATTERNS[candidate_priority]['name']} | "
            f"Folder | {item.get('size_formatted', 'unknown size')} | {item.get('name', 'candidate')}"
        )
        print(f"      {item.get('path', '(unknown path)')}")
    print("Choose one folder number, or B to return.")

    while True:
        answer = input("Folder to inspect: ").strip()
        if answer.casefold() in {"b", "back"}:
            return []
        if not answer.isdecimal() or not 1 <= int(answer) <= len(folder_entries):
            print(f"Enter a folder number from 1 to {len(folder_entries)}, or B to return.")
            continue
        folder_priority, folder_item = folder_entries[int(answer) - 1]
        break

    folder_path = folder_item.get("path")
    if not isinstance(folder_path, str) or not folder_path:
        print("This folder entry is incomplete. Scan the drive again before selecting it.")
        return []

    print("Searching the saved scan for matching files and folders inside this folder...")

    def show_search_progress(percent_complete):
        print(f"\rSearching scan file... {percent_complete:3d}%", end="", flush=True)

    try:
        expanded_results = analyze_csv(
            csv_file,
            min_size_mb,
            progress_callback=show_search_progress,
            expand_under=folder_path,
            expand_priority=None if priority == "all" else folder_priority,
        )
    except (ValueError, csv.Error, OSError) as exc:
        print(f"\nCould not search inside this folder: {describe_error(exc)}")
        return []
    print("\rFolder search complete.                              ", flush=True)

    for line in _folder_browse_skip_lines(expanded_results):
        print(line)

    expanded = expanded_results.get("expanded_candidates", [])
    entries = [
        (candidate.get("priority"), candidate.get("item"))
        for candidate in expanded
        if isinstance(candidate, dict)
    ]
    entries = [
        (candidate_priority, item)
        for candidate_priority, item in entries
        if candidate_priority in {"high", "medium", "low"} and isinstance(item, dict)
    ]
    entries.sort(key=lambda pair: (-pair[1].get("size", 0), _path_key(pair[1].get("path", ""))))
    if not entries:
        if priority == "all":
            print("No matching eligible scan entries were found inside this folder.")
        else:
            tier_name = CLEANABLE_PATTERNS[folder_priority]["name"]
            print(f"No matching entries were found for {tier_name} inside this folder.")
            print("Choose All review levels to look for entries assigned to other levels.")
        print("Only entries recorded in the scan can be selected. If you expected individual files, scan again with files included.")
        return []

    print(f"Found {len(entries)} matching scan entries inside the folder.")
    if priority != "all":
        print(f"Showing {CLEANABLE_PATTERNS[folder_priority]['name']} entries only; choose All review levels to include other levels.")
    print("Selecting a listed folder includes its eligible contents; protected data and detected projects remain protected.")
    page_size = 25
    selected = {}
    page = 0
    filter_text = ""

    while True:
        filtered_entries = [
            entry for entry in entries
            if not filter_text or filter_text in (
                str(entry[1].get("name", "")) + " " + str(entry[1].get("path", ""))
            ).casefold()
        ]
        page_count = max(1, (len(filtered_entries) + page_size - 1) // page_size)
        page = min(page, page_count - 1)
        first = page * page_size
        page_entries = filtered_entries[first:first + page_size]
        print(f"\nMatching entries: {len(filtered_entries)} | Page {page + 1} of {page_count}")
        if filter_text:
            print(f"Filter: {filter_text}")
        if not page_entries:
            print("No entries match this filter.")
        for index, (candidate_priority, item) in enumerate(page_entries, start=1):
            item_path = item.get("path", "")
            marker = "*" if _path_key(item_path) in selected else " "
            tier_name = CLEANABLE_PATTERNS[candidate_priority]["name"]
            print(
                f"{marker} [{index}] {tier_name} | {display_item_type(item)} | "
                f"{item.get('size_formatted', 'unknown size')} | {item.get('name', 'candidate')}"
            )
            print(f"      {item_path}")
        print("Numbers add or remove entries. N/P changes page; F filters by name or path; D finishes and keeps these picks; B returns without adding them.")
        answer = input("Choose entries on this page: ").strip()
        command = answer.casefold()
        if command in {"d", "done", ""}:
            return list(selected.values())
        if command in {"b", "back"}:
            print("Folder browse cancelled; its entries were not added to the cleanup plan.")
            return []
        if command in {"n", "next"}:
            if page + 1 < page_count:
                page += 1
            else:
                print("You are already on the last page.")
            continue
        if command in {"p", "previous", "prev"}:
            if page > 0:
                page -= 1
            else:
                print("You are already on the first page.")
            continue
        if command in {"f", "filter"}:
            filter_text = input("Filter by name or path text (blank clears the filter): ").strip().casefold()
            page = 0
            continue
        if command in {"a", "all"}:
            print("Choose entries by number so you can review each exact path.")
            continue
        try:
            indexes = parse_cleanup_selection(answer, len(page_entries))
        except ValueError as exc:
            print(str(exc))
            continue
        if indexes is None:
            print("Enter item numbers, N/P, F, D to keep these picks, or B to discard them and return.")
            continue
        for index in indexes:
            candidate_priority, item = page_entries[index - 1]
            key = _path_key(item.get("path", ""))
            if key in selected:
                selected.pop(key)
            else:
                selected[key] = (candidate_priority, item)


def _results_with_expanded_candidates(results, expanded_candidates):
    """Copy scan results and add only browsed items for plan validation."""
    if not expanded_candidates:
        return results
    categories = results.get("categories")
    if not isinstance(categories, dict):
        raise ValueError("Cleanup plan contains malformed candidate categories")
    copied_results = dict(results)
    copied_categories = {}
    for candidate_priority in ("high", "medium", "low"):
        category = categories.get(candidate_priority)
        if not isinstance(category, dict) or not isinstance(category.get("items"), list):
            raise ValueError("Cleanup plan contains malformed candidate categories")
        copied_category = dict(category)
        copied_items = list(category["items"])
        present_paths = {
            _path_key(item["path"])
            for item in copied_items
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        }
        for expanded_priority, item in expanded_candidates:
            if expanded_priority != candidate_priority:
                continue
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise ValueError("Cleanup plan contains a malformed expanded candidate")
            item_key = _path_key(item["path"])
            if item_key not in present_paths:
                copied_items.append(item)
                present_paths.add(item_key)
        copied_category["items"] = copied_items
        copied_categories[candidate_priority] = copied_category
    copied_results["categories"] = copied_categories
    return copied_results


def select_cleanup_candidates(results, priority, csv_file=None, min_size_mb=50):
    """Show exact candidates and return paths plus any browsed scan entries."""
    if priority not in {"high", "medium", "low", "all"}:
        raise ValueError("priority must be high, medium, low, or all")
    categories = results.get("categories")
    if not isinstance(categories, dict):
        raise ValueError("Cleanup plan contains malformed candidate categories")

    priority_order = ("high", "medium", "low") if priority == "all" else (priority,)
    entries = []
    for candidate_priority in priority_order:
        category = categories.get(candidate_priority)
        if not isinstance(category, dict) or not isinstance(category.get("items"), list):
            raise ValueError("Cleanup plan contains malformed candidate categories")
        entries.extend((candidate_priority, item) for item in category["items"])

    if not entries:
        print("No files or folders are available at that review level.")
        return ([], [])

    print("\nChoose the files and folders to include in the cleanup plan:")
    for index, (candidate_priority, item) in enumerate(entries, start=1):
        if not isinstance(item, dict):
            raise ValueError("Cleanup plan contains a malformed candidate")
        tier_name = CLEANABLE_PATTERNS[candidate_priority]["name"]
        size = item.get("size_formatted", "unknown size")
        name = item.get("name", "candidate")
        path = item.get("path", "(unknown path)")
        print(f"  [{index}] {tier_name} | {display_item_type(item)} | {size} | {name}")
        print(f"      {path}")
    print("Each row is labeled File or Folder. Choose individual files, folders, or both by number.")
    print("Choosing a folder includes files and folders inside it, even when they are not separate scan suggestions.")
    print("Protected paths and detected projects are kept. Higher-risk candidates inside selected folders are kept unless you explicitly select their listed entries too. The plan preview shows up to 12 direct items; other contents may also be removed.")
    print("To choose scan entries inside a folder, enter D. The scan must include file rows to select individual files.")
    print("Enter item numbers to add, A for all listed suggestions, D to browse inside a folder, then Enter to finish. Q cancels.")

    selected_entries = []
    selected_keys = set()
    expanded_candidates = []
    folders = [
        (candidate_priority, item) for candidate_priority, item in entries
        if display_item_type(item) == "Folder"
    ]
    while True:
        answer = input("Add entries by number, D to browse, Enter to finish, or Q to cancel: ").strip()
        if answer.casefold() in {"d", "browse"}:
            if not csv_file:
                print("The saved scan file is unavailable for folder browsing.")
                continue
            browsed = _browse_folder_candidates(
                csv_file, min_size_mb, folders, priority
            )
            for candidate_priority, item in browsed:
                key = _path_key(item["path"])
                if key not in selected_keys:
                    selected_entries.append((candidate_priority, item))
                    expanded_candidates.append((candidate_priority, item))
                    selected_keys.add(key)
            continue
        if not answer and selected_entries:
            break
        try:
            indexes = parse_cleanup_selection(answer, len(entries))
        except ValueError as exc:
            print(str(exc))
            continue

        if indexes is None:
            print("Selection cancelled; no cleanup plan was created.")
            return None
        for index in indexes:
            candidate_priority, item = entries[index - 1]
            key = _path_key(item.get("path", ""))
            if key not in selected_keys:
                selected_entries.append((candidate_priority, item))
                selected_keys.add(key)

    if not selected_entries:
        print("Selection cancelled; no cleanup plan was created.")
        return None

    selected_paths = [item["path"] for _candidate_priority, item in selected_entries]
    selected = [item for _candidate_priority, item in selected_entries]
    estimate = sum(item["size"] for item in _non_overlapping_items(selected))
    print(f"\nAdded {len(selected_paths)} selected item(s) to the cleanup plan; estimated listed size: {format_size(estimate)}")
    for candidate_priority, item in selected_entries:
        print(f"  {CLEANABLE_PATTERNS[candidate_priority]['name']} | {display_item_type(item)} | {item['size_formatted']} | {item['name']}")
        print(f"  {item['path']}")
    return selected_paths, expanded_candidates


def offer_to_run_cleanup_script(script_path):
    """Offer to launch a new plan when this window is already running as Administrator."""
    if not scan.check_admin():
        return False

    print("This window is running as Administrator.")
    print("The plan will show these entries again so you can choose which to clean and confirm.")
    try:
        while True:
            answer = input("Run the new cleanup plan now? [y/N]: ").strip().casefold()
            if answer in {"", "n", "no"}:
                print("Cleanup plan saved for later; nothing has been removed.")
                return False
            if answer in {"y", "yes"}:
                break
            print("Enter Y or N.")
    except (EOFError, KeyboardInterrupt):
        print("Launch cancelled; the cleanup plan is saved and nothing has been removed.")
        return False

    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if not powershell:
        print("PowerShell was not found. The cleanup plan is saved and can be run later.")
        return False

    print("Starting the cleanup plan in this administrator session.")
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Could not start the cleanup plan: {describe_error(exc)}")
        return False
    if result.returncode != 0:
        print(f"The cleanup plan exited with status {result.returncode}.")
    return True


SCAN_PICKER_PAGE_SIZE = 10


def _saved_scan_label(path):
    """Return a short English scanner/mode label for a saved export."""
    name = Path(path).name.casefold()
    parts = tuple(part.casefold() for part in Path(path).parts)
    if name.startswith("scan_wiztree_fast_") or ("_wiztree" in parts and "_fast" in parts):
        return "WizTree fast scan"
    if name.startswith("scan_wiztree_standard_") or ("_wiztree" in parts and "_standard" in parts):
        return "WizTree standard scan"
    if name.startswith("scan_windirstat_") or "_windirstat" in parts:
        return "WinDirStat scan"
    if (Path(path).stem.startswith("_") and len(parts) >= 2 and parts[-2] == "scan"):
        return "WinDirStat scan"
    return "Saved scan"


def prompt_existing_csv(initial_csv=None):
    """Choose a saved scan from history, or enter another scan file path."""
    if initial_csv and os.path.isfile(initial_csv):
        return initial_csv

    page = 0

    while True:
        saved_scans = scan.get_saved_scans()
        page_count = max(1, (len(saved_scans) + SCAN_PICKER_PAGE_SIZE - 1) // SCAN_PICKER_PAGE_SIZE)
        page = min(page, page_count - 1)
        first_index = page * SCAN_PICKER_PAGE_SIZE
        page_scans = saved_scans[first_index:first_index + SCAN_PICKER_PAGE_SIZE]

        clear_screen()
        print("Drive Cleanr - Choose scan results to review")
        print("=" * 60)
        if saved_scans:
            print("Saved scans (newest first):")
            for offset, scan_path in enumerate(page_scans):
                number = first_index + offset + 1
                try:
                    info = Path(scan_path).stat()
                    changed = datetime.fromtimestamp(info.st_mtime).astimezone().strftime("%Y-%m-%d %H:%M")
                    size = format_size(info.st_size)
                except (OSError, OverflowError, ValueError):
                    changed, size = "Details unavailable", "Unknown size"
                print(f"{number}) {_saved_scan_label(scan_path)} | {changed} | {size}")
                print(f"   {Path(scan_path).name}")
        else:
            print("No saved Drive Cleanr scans were found.")
        print()
        if page > 0:
            print("P) Show newer scans")
        if page + 1 < page_count:
            print("N) Show older scans")
        print("M) Choose a scan file by path")
        print("0) Back to the main menu")
        choice = input("\nEnter a scan number, M for a file path, or 0 to go back: ").strip().lower()

        if choice in {"0", "q", "back"}:
            return None
        if choice in {"n", "next"} and page + 1 < page_count:
            page += 1
            continue
        if choice in {"p", "previous"} and page > 0:
            page -= 1
            continue
        if choice in {"m", "path"}:
            manual = input("Enter the path to a supported scan CSV (or Q to go back): ").strip().strip('"')
            if manual.casefold() in {"q", "quit", "back", "cancel"}:
                continue
            if os.path.isfile(manual) and Path(manual).suffix.casefold() == ".csv":
                valid, _error = scan.validate_scan_export(manual)
                if valid:
                    return manual
                print("That file is not a supported scan CSV.")
                input("Press Enter to continue...")
            else:
                print("Scan file not found or not a CSV file. Choose an existing scan CSV.")
                input("Press Enter to continue...")
            continue

        try:
            number = int(choice)
        except ValueError:
            number = 0
        if first_index < number <= first_index + len(page_scans):
            selected = page_scans[number - first_index - 1]
            if os.path.isfile(selected) and scan._is_saved_scan_export(selected):
                return selected
            print("That saved scan changed or is no longer available. The list has been refreshed.")
            input("Press Enter to continue...")
            continue

        print("Choose a displayed scan number, N or P to change pages, M for a file path, or 0 to go back.")
        input("Press Enter to continue...")


def run_tui(initial_csv=None, min_size_mb=50):
    """Run the review menu and handle terminal cancellation cleanly."""
    try:
        _run_tui(initial_csv, min_size_mb)
    except (EOFError, KeyboardInterrupt):
        print("\nReview cancelled.")


def _run_tui(initial_csv=None, min_size_mb=50):
    """Run the interactive terminal interface."""
    csv_file = prompt_existing_csv(initial_csv)
    if not csv_file:
        return

    current_min_size = min_size_mb

    while True:
        if not os.path.isfile(csv_file):
            print(f"Error: scan file not found or the path is not a file - {csv_file}")
            input("Press Enter to choose a different scan...")
            csv_file = prompt_existing_csv()
            if not csv_file:
                return
            continue

        print("Reading scan file... 0%", end="", flush=True)

        def show_analysis_progress(percent_complete):
            print(f"\rReading scan file... {percent_complete:3d}%", end="", flush=True)

        try:
            results = analyze_csv(csv_file, current_min_size, progress_callback=show_analysis_progress)
        except (ValueError, csv.Error, OSError) as exc:
            print(f"\nCould not review this scan: {describe_error(exc)}")
            input("Press Enter to choose another scan...")
            csv_file = prompt_existing_csv()
            if not csv_file:
                return
            continue
        print("\rScan review ready.                              ", flush=True)

        while True:
            clear_screen()
            print("Drive Cleanr - Review scan results")
            print("=" * 60)
            print(f"Saved scan: {csv_file}")
            print(f"Minimum item size shown: {current_min_size} MB")
            print()
            print_report(results, item_limit=5)
            print()
            print("1) View all suggested files and folders")
            print("2) Save the suggestions and separate manual-review list to a text file")
            print("3) Choose individual files, folders, or both for a cleanup plan")
            print("4) Change the minimum item size shown")
            print("5) Review a different scan")
            print("6) Review the largest files outside cleanup suggestions")
            print("0) Back")

            choice = input("\nSelect an option [0-6]: ").strip().lower()

            if choice == "1":
                clear_screen()
                print("All suggested files and folders")
                print("=" * 60)
                print_report(results, show_all_items=True, item_limit=9999)
                input("\nPress Enter to go back...")
            elif choice == "2":
                default_name = f"{Path(csv_file).stem}.cleanup-items.txt"
                output_path = input(f"Save the review list to [{default_name}]: ").strip().strip('"') or default_name
                try:
                    write_item_list_report(results, output_path)
                    print(f"Review list saved to: {output_path}")
                except (ValueError, OSError) as exc:
                    print(f"Could not save the review list: {describe_error(exc)}")
                input("Press Enter to continue...")
            elif choice == "3":
                print("Review groups: high = lower risk, medium = review carefully, low = confirm impact, all = every group.")
                priority = prompt_choice("Choose groups to include", ["high", "medium", "low", "all"], default="high")
                selection = select_cleanup_candidates(
                    results, priority, csv_file=csv_file, min_size_mb=current_min_size
                )
                if not selection:
                    input("Press Enter to continue...")
                    continue
                selected_paths, expanded_candidates = selection
                if not selected_paths:
                    input("Press Enter to continue...")
                    continue
                default_name = f"{Path(csv_file).stem}.clean.ps1"
                output_path = input(f"Save the PowerShell cleanup plan to [{default_name}]: ").strip().strip('"') or default_name
                try:
                    plan_results = _results_with_expanded_candidates(results, expanded_candidates)
                    generate_clean_script(
                        plan_results, output_path, priority, selected_paths=selected_paths
                    )
                    print(f"Cleanup plan saved to: {output_path}")
                    offer_to_run_cleanup_script(output_path)
                except (ValueError, OSError) as exc:
                    print(f"Could not save the cleanup plan: {describe_error(exc)}")
                input("Press Enter to continue...")
            elif choice == "6":
                try:
                    selected_manual_files = select_manual_review_files(results)
                except ValueError as exc:
                    print(f"Could not prepare the manual-review list: {describe_error(exc)}")
                    input("Press Enter to continue...")
                    continue
                if not selected_manual_files:
                    input("Press Enter to continue...")
                    continue
                confirmation = input(
                    "Type REVIEWED to save a plan for these exact files, or Q to cancel: "
                ).strip()
                if confirmation != "REVIEWED":
                    print("Cancelled; no manual-review plan was created.")
                    input("Press Enter to continue...")
                    continue
                default_name = f"{Path(csv_file).stem}.manual-review.clean.ps1"
                output_path = input(
                    f"Save the manual-review PowerShell plan to [{default_name}]: "
                ).strip().strip('"') or default_name
                try:
                    generate_clean_script(
                        results, output_path, "manual",
                        selected_paths=[item["path"] for item in selected_manual_files],
                        manual_review_confirmed=True,
                    )
                    print(f"Manual-review plan saved to: {output_path}")
                    offer_to_run_cleanup_script(output_path)
                except (ValueError, OSError) as exc:
                    print(f"Could not save the manual-review plan: {describe_error(exc)}")
                input("Press Enter to continue...")
            elif choice == "4":
                new_size = input(f"New minimum item size in MB [{current_min_size}]: ").strip()
                if new_size:
                    try:
                        current_min_size = max(1, int(new_size))
                    except ValueError:
                        print("Please enter a valid integer.")
                        input("Press Enter to continue...")
                        continue
                break
            elif choice == "5":
                new_csv = prompt_existing_csv()
                if new_csv:
                    csv_file = new_csv
                else:
                    return
                break
            elif choice in {"0", "q", "quit", "exit"}:
                return
            else:
                print("Invalid choice.")
                input("Press Enter to continue...")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Review a drive scan and choose files or folders for a cleanup plan')
    parser.add_argument('csv_file', nargs='?', help='Path to a WizTree or WinDirStat scan file')
    parser.add_argument('--min-size', type=int, default=50, help='Minimum file or folder size to show, in MB (default: 50)')
    parser.add_argument('--output', help='Where to save the PowerShell cleanup plan')
    parser.add_argument('--priority', choices=['high', 'medium', 'low', 'all'], default='high',
                        help='Review group to include in the cleanup plan')
    parser.add_argument('--list-items', action='store_true', help='List all suggested files and folders by review group')
    parser.add_argument('--list-output', help='Save the suggested file and folder list to a text file')
    parser.add_argument('--item-limit', type=int, default=10, help='Number of items to show per category in the normal report')
    parser.add_argument('--tui', action='store_true', help='Start the interactive terminal UI')
    parser.add_argument('--json', action='store_true', help='Output JSON format')

    args = parser.parse_args()

    if args.tui:
        try:
            run_tui(args.csv_file, args.min_size)
        except (EOFError, KeyboardInterrupt):
            print("\nReview cancelled.")
        return

    if not args.csv_file:
        parser.error('a scan file is required unless --tui is used')

    if not os.path.isfile(args.csv_file):
        print(f"Error: scan file not found or the path is not a file - {args.csv_file}")
        sys.exit(1)

    try:
        results = analyze_csv(args.csv_file, args.min_size)
    except (ValueError, csv.Error, OSError) as exc:
        parser.error(f"could not review scan file: {describe_error(exc)}")

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        print_report(results, show_all_items=args.list_items, item_limit=args.item_limit)

    if args.output:
        try:
            generate_clean_script(results, args.output, args.priority)
        except (ValueError, OSError) as exc:
            parser.error(f"could not save cleanup plan: {describe_error(exc)}")
        print(f"\nCleanup plan saved to: {args.output}")

    if args.list_output:
        try:
            write_item_list_report(results, args.list_output)
        except (ValueError, OSError) as exc:
            parser.error(f"could not save file and folder list: {describe_error(exc)}")
        print(f"\nFile and folder list saved to: {args.list_output}")


if __name__ == "__main__":
    main()
