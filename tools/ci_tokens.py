"""Ephemeral privilege reduction only. Never enables privileges or changes accounts."""
import ctypes as c
from ctypes import wintypes as w
from guardian import windows as win
from guardian.ipc import token_details


class SIDATTR(c.Structure):_fields_=[('sid',win.P),('attributes',w.DWORD)]
class GROUPS(c.Structure):_fields_=[('count',w.DWORD),('groups',SIDATTR*1)]
class LUID(c.Structure):_fields_=[('low',w.DWORD),('high',w.LONG)]
class PRIV(c.Structure):_fields_=[('luid',LUID),('attributes',w.DWORD)]
class PRIVS(c.Structure):_fields_=[('count',w.DWORD),('privileges',PRIV*1)]


def query(token,kind):
    size=w.DWORD();win.get_token(token,kind,None,0,c.byref(size));buf=c.create_string_buffer(size.value)
    win.check(win.get_token(token,kind,buf,size,c.byref(size)));return buf


def inspect(token):
    result=token_details(token);groups=query(token,2);count=c.cast(groups,c.POINTER(w.DWORD))[0]
    entries=c.cast(c.addressof(groups)+GROUPS.groups.offset,c.POINTER(SIDATTR))
    result['administrators_enabled']=any(win.sid_string(entries[i].sid)=='S-1-5-32-544' and bool(entries[i].attributes&4) for i in range(count))
    privs=query(token,3);count=c.cast(privs,c.POINTER(w.DWORD))[0]
    entries=c.cast(c.addressof(privs)+PRIVS.privileges.offset,c.POINTER(PRIV));names=[];attributes={}
    lookup=win.api(win.a,'LookupPrivilegeNameW',w.BOOL,w.LPCWSTR,c.POINTER(LUID),w.LPWSTR,c.POINTER(w.DWORD))
    for i in range(count):
        size=w.DWORD(128);buf=c.create_unicode_buffer(128);win.check(lookup(None,c.byref(entries[i].luid),buf,c.byref(size)))
        names.append(buf.value)
        attributes[buf.value]={'attributes':int(entries[i].attributes),'enabled':bool(entries[i].attributes&2)}
    result['present_privileges']=sorted(names);result['privilege_attributes']=attributes
    for name,kind in (('token_type',8),('session_id',12),('elevation_type',18),('has_restrictions',21)):
        result[name]=int(c.cast(query(token,kind),c.POINTER(w.DWORD))[0])
    return result


def reduced_token(original):
    token=w.HANDLE();sid=win.P()
    # DISABLE_MAX_PRIVILEGE | LUA_TOKEN. Never SANDBOX_INERT.
    win.check(win.api(win.a,'CreateRestrictedToken',w.BOOL,w.HANDLE,w.DWORD,w.DWORD,win.P,w.DWORD,win.P,w.DWORD,win.P,c.POINTER(w.HANDLE))(
        original,1|4,0,None,0,None,0,None,c.byref(token)))
    try:
        win.check(win.api(win.a,'ConvertStringSidToSidW',w.BOOL,w.LPCWSTR,c.POINTER(win.P))('S-1-16-8192',c.byref(sid)))
        label=SIDATTR(sid,0x20)
        size=c.sizeof(label)+win.api(win.a,'GetLengthSid',w.DWORD,win.P)(sid)
        win.check(win.api(win.a,'SetTokenInformation',w.BOOL,w.HANDLE,c.c_int,win.P,w.DWORD)(token,25,c.byref(label),size))
        return token
    except Exception:win.close(token);raise
    finally:
        if sid:win.local_free(sid)


def acceptable(observed,user_sha256):
    return (observed['user_sha256']==user_sha256 and not observed['elevated']
      and not observed['administrators_enabled'] and not observed['appcontainer']
      and observed['integrity_sid']=='S-1-16-8192'
      and set(observed['present_privileges'])<={'SeChangeNotifyPrivilege'})
