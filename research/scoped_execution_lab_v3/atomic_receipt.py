"""Candidate-only atomic receipt publication. Research Windows/NTFS semantics.
No authority: caller must independently verify worker outcome before publication.
"""
import os,json,hashlib,ctypes
from .lifecycle_support import crash_gate
from pathlib import Path
from ctypes import wintypes
def directory_flush(path):
 k=ctypes.WinDLL("kernel32",use_last_error=True)
 k.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
 k.CreateFileW.restype=wintypes.HANDLE
 k.FlushFileBuffers.argtypes=[wintypes.HANDLE];k.FlushFileBuffers.restype=wintypes.BOOL
 k.CloseHandle.argtypes=[wintypes.HANDLE];k.CloseHandle.restype=wintypes.BOOL
 h=k.CreateFileW(str(Path(path).resolve()),0xC0000000,7,None,3,0x02000000,None)
 if h==ctypes.c_void_p(-1).value:return False
 try:return bool(k.FlushFileBuffers(h))
 finally:k.CloseHandle(h)
def publish(out,receipt,canonical):
 out=Path(out);out.mkdir(parents=True,exist_ok=True)
 final=out/"receipt.json";temp=out/"receipt.tmp"
 if temp.exists() or final.exists():raise ValueError("RECEIPT_ALREADY_PRESENT")
 data=canonical(receipt)+b"\n"
 with temp.open("xb",buffering=0) as f:
  first=len(data)//2
  if f.write(data[:first])!=first:raise IOError("SHORT_WRITE")
  crash_gate(out,"partial_receipt")
  if f.write(data[first:])!=len(data)-first:raise IOError("SHORT_WRITE")
  crash_gate(out,"before_fsync")
  f.flush();os.fsync(f.fileno())
  crash_gate(out,"after_fsync")
 os.replace(temp,final)
 crash_gate(out,"after_replace")
 if not directory_flush(out):raise IOError("DIRECTORY_DURABILITY_UNAVAILABLE")
 if final.read_bytes()!=data:raise IOError("RECEIPT_READBACK_MISMATCH")
 return hashlib.sha256(data).hexdigest()
