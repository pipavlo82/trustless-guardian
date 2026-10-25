"""Durable intent and conservative recovery. No file/SQLite atomicity claim."""
import sqlite3
from contextlib import closing
from .policy import canonical, parse, digest


def provision(path):
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('CREATE TABLE operations(nonce TEXT PRIMARY KEY, state TEXT NOT NULL, intent TEXT NOT NULL, receipt TEXT)')
        db.execute('PRAGMA user_version=2')


class Journal:
    def __init__(self,path):
        if not path.is_file():raise OSError('JOURNAL_MISSING')
        self.db=sqlite3.connect(path,timeout=0.25)
        try:
            self.db.execute('PRAGMA synchronous=FULL')
            if self.db.execute('PRAGMA user_version').fetchone()[0]!=2:raise ValueError('JOURNAL_VERSION')
            self.db.execute('SELECT nonce,state,intent,receipt FROM operations LIMIT 0')
        except Exception:self.close();raise
    def close(self):self.db.close()
    def rows(self):
        rows=[{'nonce':n,'state':s,'intent':parse(i),'receipt':parse(r) if r else None}
              for n,s,i,r in self.db.execute('SELECT nonce,state,intent,receipt FROM operations ORDER BY rowid')]
        if any(r['state'] not in {'PREPARED','COMMITTED','ABORTED','RECOVERY_REQUIRED'} for r in rows):  # V02 journal_state
            raise ValueError('JOURNAL_UNKNOWN_STATE')
        return rows
    def recover(self,current,identity,policy_pin):
        for row in self.rows():
            if row['state']!='PREPARED':continue
            i=row['intent']
            # Pre-state equality only supports an abort when intended bytes differ.
            # Same-byte writes cannot be distinguished from never-started writes.
            state=('ABORTED' if digest(current)==i['before_sha256'] and identity==i['resource_identity']
                   and policy_pin==i['policy_sha256'] else 'RECOVERY_REQUIRED')
            if i['before_sha256']==i['after_sha256']:state='RECOVERY_REQUIRED'  # V03 same_bytes
            with self.db:self.db.execute('UPDATE operations SET state=? WHERE nonce=?',(state,row['nonce']))
        return self.rows()
    def prepare(self,nonce,intent):
        with self.db:
            self.db.execute('INSERT INTO operations VALUES(?,?,?,NULL)',(nonce,'PREPARED',canonical(intent).decode()))
    def commit(self,nonce,receipt):
        with self.db:
            self.db.execute('UPDATE operations SET state=?,receipt=? WHERE nonce=? AND state=?',
                            ('COMMITTED',canonical(receipt).decode(),nonce,'PREPARED'))
            if self.db.execute('SELECT changes()').fetchone()[0]!=1:raise ValueError('JOURNAL_COMMIT')
